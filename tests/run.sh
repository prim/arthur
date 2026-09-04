#!/usr/bin/env bash
set -euo pipefail

ARTHUR_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARTHUR_BIN=${ARTHUR_BIN:-"$ARTHUR_DIR/arthur"}
if [[ $ARTHUR_BIN != /* ]]; then
    ARTHUR_BIN=$(CDPATH= cd -- "$(dirname -- "$ARTHUR_BIN")" && pwd)/$(basename -- "$ARTHUR_BIN")
fi
CASE=${1:-all}
CASE_RAN=0
REPO_ROOT=$(CDPATH= cd -- "$ARTHUR_DIR/../.." && pwd)
REPO_TMP="$REPO_ROOT/tmp"
mkdir -p "$REPO_TMP"
TEST_TMP=$(mktemp -d "$REPO_TMP/arthur-tests.XXXXXX")
TARGET_PIDS=()

cleanup() {
    for pid in "${TARGET_PIDS[@]}"; do
        kill -KILL "$pid" 2>/dev/null || true
    done
    rm -rf "$TEST_TMP"
}
trap cleanup EXIT INT TERM

wait_for_log() {
    local file=$1
    local text=$2
    for _ in $(seq 1 200); do
        if grep -q "$text" "$file" 2>/dev/null; then
            return 0
        fi
        sleep 0.05
    done
    echo "timed out waiting for '$text' in $file" >&2
    return 1
}

start_fixture() {
    local mode=$1
    shift
    "$TEST_TMP/fixture" "$mode" "$@" >"$TEST_TMP/fixture.log" 2>&1 &
    FIXTURE_PID=$!
    TARGET_PIDS+=("$FIXTURE_PID")
    wait_for_log "$TEST_TMP/fixture.log" ready
}

expect_status() {
    local expected=$1
    shift
    set +e
    "$@"
    local rc=$?
    set -e
    if [[ $rc -ne $expected ]]; then
        echo "expected status $expected, got $rc: $*" >&2
        return 1
    fi
}

wait_for_process_exit() {
    local pid=$1
    for _ in $(seq 1 400); do
        if [[ ! -r /proc/$pid/stat ]]; then
            return 0
        fi
        if [[ $(awk '{print $3}' "/proc/$pid/stat") == Z ]]; then
            return 0
        fi
        sleep 0.025
    done
    echo "timed out waiting for process $pid to exit" >&2
    return 1
}

wait_for_tracer() {
    local pid=$1
    for _ in $(seq 1 1000); do
        if [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$pid/status" 2>/dev/null || true) != 0 ]]; then
            return 0
        fi
        sleep 0.001
    done
    echo "timed out waiting for Arthur to trace $pid" >&2
    return 1
}

find_timeout_child() {
    local timeout_pid=$1
    local child=
    for _ in $(seq 1 200); do
        child=$(pgrep -P "$timeout_pid" | head -n 1 || true)
        if [[ -n $child ]]; then
            printf '%s\n' "$child"
            return 0
        fi
        sleep 0.01
    done
    echo "cannot find Arthur child under timeout $timeout_pid" >&2
    return 1
}

flip_byte() {
    local file=$1
    local offset=$2
    local old_byte new_byte
    old_byte=$(od -An -tu1 -j "$offset" -N 1 "$file")
    new_byte=$((old_byte ^ 1))
    printf '%b' "\\$(printf '%03o' "$new_byte")" | dd \
        of="$file" bs=1 seek="$offset" conv=notrunc status=none
}

${CXX:-g++} -std=c++11 -Wall -Wextra -Wno-missing-field-initializers \
    -I"$ARTHUR_DIR/src" \
    -I"$ARTHUR_DIR/include" \
    "$ARTHUR_DIR/tests/proc_test.cc" "$ARTHUR_DIR/src/proc.cc" \
    -o "$TEST_TMP/proc_test"
${CC:-gcc} -std=c11 -Wall -Wextra -pthread \
    "$ARTHUR_DIR/tests/fixture.c" -o "$TEST_TMP/fixture"
if [[ $CASE == static-fallback || $CASE == all ]]; then
    ${CC:-gcc} -nostdlib -static "$ARTHUR_DIR/tests/static_target.S" \
        -o "$TEST_TMP/static_target"
fi
${CC:-gcc} -std=c11 -Wall -Wextra -shared -fPIC \
    "$ARTHUR_DIR/tests/fclose_fail.c" -ldl -o "$TEST_TMP/fclose_fail.so"
if [[ $(uname -m) == aarch64 ]]; then
    LZ4_TEST_LIBRARY=-llz4-arm64
    XSTATE_NOTE_COUNT=0
else
    LZ4_TEST_LIBRARY=-llz4-x64
    XSTATE_NOTE_COUNT=1
fi
${CXX:-g++} -std=c++11 -Wall -Wextra -Wno-missing-field-initializers \
    -I"$ARTHUR_DIR/src" \
    -I"$ARTHUR_DIR/include" \
    "$ARTHUR_DIR/tests/acore_format_test.cc" "$ARTHUR_DIR/src/lz4.cc" \
    -L"$ARTHUR_DIR/lib" "$LZ4_TEST_LIBRARY" -no-pie \
    -o "$TEST_TMP/acore_format_test"
${CXX:-g++} -std=c++11 -Wall -Wextra \
    -I"$ARTHUR_DIR/src" \
    "$ARTHUR_DIR/tests/core_note_test.cc" \
    -o "$TEST_TMP/core_note_test"

if [[ $CASE == proc || $CASE == all ]]; then
CASE_RAN=1
    "$TEST_TMP/proc_test"
fi

if [[ $CASE == cli || $CASE == all ]]; then
CASE_RAN=1
printf 'cli operand validation\n' >"$TEST_TMP/cli.input"
expect_status 2 "$ARTHUR_BIN" -1 -o "$TEST_TMP/cli.z4" \
    "$TEST_TMP/cli.input" ignored-extra
if [[ -e "$TEST_TMP/cli.z4" ]]; then
    echo "test_compress accepted an extra operand and created output" >&2
    exit 1
fi
expect_status 0 "$ARTHUR_BIN" -1 -o "$TEST_TMP/valid-cli.z4" \
    "$TEST_TMP/cli.input"
expect_status 2 "$ARTHUR_BIN" -2 "$TEST_TMP/valid-cli.z4" \
    "$TEST_TMP/cli.output" ignored-extra
if [[ -e "$TEST_TMP/cli.output" ]]; then
    echo "test_decompress accepted an extra operand and created output" >&2
    exit 1
fi
expect_status 2 "$ARTHUR_BIN" -c missing.acore \
    -o "$TEST_TMP/cli.core" ignored-extra
expect_status 2 "$ARTHUR_BIN" -p 2147483647 -1 \
    -o "$TEST_TMP/cli.acore" ignored-extra

# GNU option permutation and `--` must preserve exact operands, including
# filenames beginning with '-'. An empty output name must fail without leaving
# the same-directory temporary file used by atomic output.
expect_status 0 "$ARTHUR_BIN" "$TEST_TMP/cli.input" -1 \
    -o "$TEST_TMP/cli-permuted.z4"
expect_status 0 "$ARTHUR_BIN" "$TEST_TMP/cli-permuted.z4" -2 \
    -o "$TEST_TMP/cli-permuted.output"
cmp "$TEST_TMP/cli.input" "$TEST_TMP/cli-permuted.output"
(
    cd "$TEST_TMP"
    printf 'dash operand\n' > ./-cli-input
    expect_status 0 "$ARTHUR_BIN" -1 -- -cli-input
    expect_status 0 "$ARTHUR_BIN" -2 -- -cli-input.z4 -cli-output
    cmp -- -cli-input -cli-output
)
mkdir "$TEST_TMP/empty-output-cwd"
(
    cd "$TEST_TMP/empty-output-cwd"
    expect_status 255 "$ARTHUR_BIN" -1 -o '' ../cli.input
)
if find "$TEST_TMP/empty-output-cwd" -maxdepth 1 -name '.tmp.*' | grep -q .; then
    echo "empty output name left an atomic temporary file" >&2
    exit 1
fi
fi

if [[ $CASE == stream || $CASE == all ]]; then
CASE_RAN=1
: >"$TEST_TMP/stream-empty.input"
expect_status 0 "$ARTHUR_BIN" -1 -o "$TEST_TMP/stream-empty.z4" \
    "$TEST_TMP/stream-empty.input" >"$TEST_TMP/stream-empty.log" 2>&1
EMPTY_REPORTED=$(sed -n 's/.* into \([0-9][0-9]*\) bytes.*/\1/p' \
    "$TEST_TMP/stream-empty.log")
EMPTY_ACTUAL=$(stat -c %s "$TEST_TMP/stream-empty.z4")
if [[ $EMPTY_REPORTED != "$EMPTY_ACTUAL" ]]; then
    echo "test_compress statistics do not match the physical empty stream" >&2
    exit 1
fi
"$TEST_TMP/acore_format_test" --empty-stat \
    >"$TEST_TMP/stream-empty-stat.log" 2>&1
grep -q "Compressed 0 bytes into 0 bytes ==> 0.00%" \
    "$TEST_TMP/stream-empty-stat.log"
if grep -Eiq '(^|[^[:alpha:]])(nan|inf)([^[:alpha:]]|$)' \
    "$TEST_TMP/stream-empty-stat.log"; then
    echo "empty stream reported a non-finite compression ratio" >&2
    exit 1
fi
"$TEST_TMP/acore_format_test" --stat "$TEST_TMP/stream-stat.acore" \
    >"$TEST_TMP/stream-stat.log" 2>&1
STAT_REPORTED=$(sed -n 's/.* into \([0-9][0-9]*\) bytes.*/\1/p' \
    "$TEST_TMP/stream-stat.log")
STAT_ACTUAL=$(stat -c %s "$TEST_TMP/stream-stat.acore")
if [[ $STAT_REPORTED != "$STAT_ACTUAL" ]] ||
   ! grep -Eq '==> [0-9]+\.[0-9][0-9]%$' "$TEST_TMP/stream-stat.log"; then
    echo "compression statistics do not match the physical stream size" >&2
    exit 1
fi
printf 'seekable stream validation\n' >"$TEST_TMP/stream.input"
expect_status 0 "$ARTHUR_BIN" -1 -o "$TEST_TMP/stream.z4" \
    "$TEST_TMP/stream.input"
# A checksummed stream must use the dedicated STREAM block type. The helper
# writes an otherwise valid stream with a PROCESS block and a matching CRC.
"$TEST_TMP/acore_format_test" --bad-stream "$TEST_TMP/wrong-type.z4"
printf 'existing-stream-output\n' >"$TEST_TMP/wrong-type.output"
cp "$TEST_TMP/wrong-type.output" "$TEST_TMP/wrong-type.expected"
set +e
"$ARTHUR_BIN" -2 "$TEST_TMP/wrong-type.z4" \
    "$TEST_TMP/wrong-type.output" >"$TEST_TMP/wrong-type.log" 2>&1
WRONG_TYPE_RC=$?
set -e
if [[ $WRONG_TYPE_RC -eq 0 ]] ||
   ! cmp -s "$TEST_TMP/wrong-type.expected" "$TEST_TMP/wrong-type.output"; then
    echo "non-STREAM checksummed stream was accepted or replaced prior output" >&2
    exit 1
fi
grep -q "expected STREAM block" "$TEST_TMP/wrong-type.log"
mkfifo "$TEST_TMP/stream.fifo"
cat "$TEST_TMP/stream.z4" >"$TEST_TMP/stream.fifo" &
WRITER_PID=$!
TARGET_PIDS+=("$WRITER_PID")
printf 'existing-stream-output\n' >"$TEST_TMP/stream.output"
cp "$TEST_TMP/stream.output" "$TEST_TMP/stream.expected"
set +e
"$ARTHUR_BIN" -2 "$TEST_TMP/stream.fifo" "$TEST_TMP/stream.output" \
    >"$TEST_TMP/stream.log" 2>&1
STREAM_RC=$?
wait "$WRITER_PID" 2>/dev/null
set -e
if [[ $STREAM_RC -eq 0 ]] ||
   ! cmp -s "$TEST_TMP/stream.expected" "$TEST_TMP/stream.output"; then
    echo "non-seekable input was accepted or replaced prior output" >&2
    exit 1
fi
grep -q "seekable input" "$TEST_TMP/stream.log"
fi

# Stopping Arthur itself must release every ptrace relationship, leave the
# target running, and remove the uncommitted monitor seed file.
if [[ $CASE == monitor-stop || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory-spin 8
"$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/monitor-stop.acore" >"$TEST_TMP/monitor-stop.log" 2>&1 &
MONITOR_PID=$!
TARGET_PIDS+=("$MONITOR_PID")
wait_for_log "$TEST_TMP/monitor-stop.log" "Launched in monitor mode"
kill -TERM "$MONITOR_PID"
expect_status 0 wait "$MONITOR_PID"
if ! kill -0 "$FIXTURE_PID" 2>/dev/null ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]]; then
    echo "stopping monitor terminated or retained ptrace ownership of target" >&2
    exit 1
fi
if [[ -e "$TEST_TMP/monitor-stop.acore" ]] ||
   find "$TEST_TMP" -maxdepth 1 -name 'monitor-stop.acore.tmp.*' | grep -q .; then
    echo "stopping monitor retained an output or temporary file" >&2
    exit 1
fi
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e

start_fixture memory-spin 8
"$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/monitor-stop-group.acore" \
    >"$TEST_TMP/monitor-stop-group.log" 2>&1 &
GROUP_MONITOR_PID=$!
TARGET_PIDS+=("$GROUP_MONITOR_PID")
wait_for_log "$TEST_TMP/monitor-stop-group.log" "Launched in monitor mode"
kill -STOP "$FIXTURE_PID"
for _ in $(seq 1 200); do
    GROUP_STOP_STATE=$(awk '{print $3}' "/proc/$FIXTURE_PID/stat")
    if [[ $GROUP_STOP_STATE =~ ^[Tt]$ ]]; then
        break
    fi
    sleep 0.01
done
if [[ ! $GROUP_STOP_STATE =~ ^[Tt]$ ]]; then
    echo "monitored fixture did not enter group-stop" >&2
    exit 1
fi
kill -TERM "$GROUP_MONITOR_PID"
expect_status 0 wait "$GROUP_MONITOR_PID"
if [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]] ||
   [[ ! $(awk '{print $3}' "/proc/$FIXTURE_PID/stat") =~ ^[Tt]$ ]] ||
   [[ -e "$TEST_TMP/monitor-stop-group.acore" ]]; then
    echo "stopping monitor changed a target group-stop or retained output" >&2
    exit 1
fi
kill -CONT "$FIXTURE_PID"
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e

start_fixture memory-spin 8
ARTHUR_FAIL_SIGWAITINFO=1 LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/sigwait-fail.acore" >"$TEST_TMP/sigwait-fail.log" 2>&1 &
SIGWAIT_MONITOR_PID=$!
TARGET_PIDS+=("$SIGWAIT_MONITOR_PID")
set +e
wait "$SIGWAIT_MONITOR_PID"
SIGWAIT_RC=$?
set -e
if [[ $SIGWAIT_RC -eq 0 ]] || ! kill -0 "$FIXTURE_PID" 2>/dev/null ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]]; then
    echo "sigwaitinfo failure succeeded, killed target, or retained ptrace ownership" >&2
    exit 1
fi
if [[ -e "$TEST_TMP/sigwait-fail.acore" ]] ||
   find "$TEST_TMP" -maxdepth 1 -name 'sigwait-fail.acore.tmp.*' | grep -q .; then
    echo "sigwaitinfo failure retained an output or temporary file" >&2
    exit 1
fi
grep -q "monitor sigwaitinfo failed" "$TEST_TMP/sigwait-fail.log"
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
fi

# Monitor event collection errors are state-machine failures, not empty polls.
# Arthur must detach and return nonzero instead of waiting forever or changing
# a job-control stop into an ordinary signal resume.
if [[ $CASE == monitor-errors || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory-spin 8
timeout 5s env ARTHUR_FAIL_WAITPID=1 LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/waitpid-error.acore" >"$TEST_TMP/waitpid-error.log" 2>&1 &
WAITPID_WRAPPER_PID=$!
TARGET_PIDS+=("$WAITPID_WRAPPER_PID")
wait_for_log "$TEST_TMP/waitpid-error.log" "Launched in monitor mode"
set +e
wait "$WAITPID_WRAPPER_PID"
WAITPID_MONITOR_RC=$?
set -e
if [[ $WAITPID_MONITOR_RC -eq 0 || $WAITPID_MONITOR_RC -eq 124 ]] ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]] ||
   [[ $(awk '{print $3}' "/proc/$FIXTURE_PID/stat") == [Tt] ]]; then
    echo "monitor ignored waitpid EIO, timed out, retained ownership, or stopped target" >&2
    exit 1
fi
grep -q "monitor: wait for thread.*failed" "$TEST_TMP/waitpid-error.log"
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e

start_fixture memory-spin 8
timeout 5s env ARTHUR_FAIL_LISTEN=1 LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/listen-error.acore" >"$TEST_TMP/listen-error.log" 2>&1 &
LISTEN_WRAPPER_PID=$!
TARGET_PIDS+=("$LISTEN_WRAPPER_PID")
wait_for_log "$TEST_TMP/listen-error.log" "Launched in monitor mode"
kill -STOP "$FIXTURE_PID"
set +e
wait "$LISTEN_WRAPPER_PID"
LISTEN_MONITOR_RC=$?
set -e
if [[ $LISTEN_MONITOR_RC -eq 0 || $LISTEN_MONITOR_RC -eq 124 ]] ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]]; then
    echo "monitor ignored LISTEN EIO, timed out, or retained target ownership" >&2
    exit 1
fi
grep -q "listen on group-stopped thread.*failed" "$TEST_TMP/listen-error.log"
kill -CONT "$FIXTURE_PID" 2>/dev/null || true
kill -KILL "$FIXTURE_PID" 2>/dev/null || true
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
fi

# Once the target has resumed, every failure in the late recovery helper must
# end monitor service. Continuing would leave TRACEFORK or a stopped leader in
# an unknown state. A forced child-memory EOF enters that helper deterministically.
if [[ $CASE == recovery-errors || $CASE == all ]]; then
CASE_RAN=1
for recovery_fault in clear interrupt cont; do
    start_fixture memory-spin 8
    recovery_env=(ARTHUR_FAIL_PROC_MEM_EOF=1)
    case $recovery_fault in
        clear) recovery_env+=(ARTHUR_FAIL_CLEAR_TRACEFORK=1) ;;
        interrupt) recovery_env+=(ARTHUR_FAIL_INTERRUPT_AFTER_CHILD_KILL=1) ;;
        cont) recovery_env+=(ARTHUR_FAIL_CONT_AFTER_CLEAR=1) ;;
    esac
    timeout 15s env "${recovery_env[@]}" LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
        "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
        -o "$TEST_TMP/recovery-$recovery_fault.acore" \
        >"$TEST_TMP/recovery-$recovery_fault.log" 2>&1 &
    RECOVERY_WRAPPER_PID=$!
    TARGET_PIDS+=("$RECOVERY_WRAPPER_PID")
    wait_for_log "$TEST_TMP/recovery-$recovery_fault.log" "Launched in monitor mode"
    RECOVERY_MONITOR_PID=$(find_timeout_child "$RECOVERY_WRAPPER_PID")
    kill -USR1 "$RECOVERY_MONITOR_PID"
    set +e
    wait "$RECOVERY_WRAPPER_PID"
    RECOVERY_RC=$?
    set -e
    if [[ $RECOVERY_RC -eq 0 || $RECOVERY_RC -eq 124 ]] ||
       [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]] ||
       find "$TEST_TMP" -maxdepth 1 -name "recovery-$recovery_fault.acore*" | grep -q .; then
        echo "late $recovery_fault recovery failure continued, timed out, retained ptrace, or published" >&2
        exit 1
    fi
    grep -q "failed to dump memory" "$TEST_TMP/recovery-$recovery_fault.log"
    kill -KILL "$FIXTURE_PID" 2>/dev/null || true
    set +e
    wait "$FIXTURE_PID" 2>/dev/null
    set -e
done
fi

# A failed DETACH(SIGKILL) must not leave the forked COW snapshot as a stopped
# tracee of a long-lived monitor. Arthur falls back to an explicit SIGKILL and
# drives the child through any ptrace exit stop before publishing.
if [[ $CASE == child-cleanup || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory-spin 8
(
    cd "$TEST_TMP"
    exec timeout 20s env ARTHUR_FAIL_CHILD_DETACH=1 \
        LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
        "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
        -o "$TEST_TMP/child-cleanup-seed.acore"
) >"$TEST_TMP/child-cleanup.log" 2>&1 &
CHILD_CLEANUP_WRAPPER_PID=$!
TARGET_PIDS+=("$CHILD_CLEANUP_WRAPPER_PID")
wait_for_log "$TEST_TMP/child-cleanup.log" "Launched in monitor mode"
CHILD_CLEANUP_MONITOR_PID=$(find_timeout_child "$CHILD_CLEANUP_WRAPPER_PID")
kill -USR1 "$CHILD_CLEANUP_MONITOR_PID"
wait_for_log "$TEST_TMP/child-cleanup.log" "writing out acore finished"
grep -q "using kill fallback" "$TEST_TMP/child-cleanup.log"
CHILD_CLEANUP_SNAPSHOT=$(find "$TEST_TMP" -maxdepth 1 -type f \
    -name "acore.$FIXTURE_PID.*" -print -quit)
if [[ -z $CHILD_CLEANUP_SNAPSHOT ]] ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") \
      != "$CHILD_CLEANUP_MONITOR_PID" ]]; then
    echo "child detach fallback did not publish or lost monitor ownership" >&2
    exit 1
fi
expect_status 0 "$ARTHUR_BIN" -c "$CHILD_CLEANUP_SNAPSHOT" \
    -o "$TEST_TMP/child-cleanup.core"
kill -TERM "$FIXTURE_PID"
expect_status 143 wait "$FIXTURE_PID"
expect_status 0 wait "$CHILD_CLEANUP_WRAPPER_PID"
fi

# Losing a TRACEFORK event's child PID means Arthur cannot release the kernel's
# auto-attached child. The snapshot transaction and monitor lifecycle must fail
# closed; process exit then releases the otherwise unknowable tracee.
if [[ $CASE == event-identity || $CASE == all ]]; then
CASE_RAN=1
start_fixture fork-cont
(
    cd "$TEST_TMP"
    exec timeout 20s env ARTHUR_FAIL_GETEVENTMSG_AFTER_CHILD_KILL=1 \
        LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
        "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
        -o "$TEST_TMP/event-identity-seed.acore"
) >"$TEST_TMP/event-identity.log" 2>&1 &
EVENT_WRAPPER_PID=$!
TARGET_PIDS+=("$EVENT_WRAPPER_PID")
wait_for_log "$TEST_TMP/event-identity.log" "Launched in monitor mode"
EVENT_MONITOR_PID=$(find_timeout_child "$EVENT_WRAPPER_PID")
kill -USR1 "$EVENT_MONITOR_PID"
set +e
wait "$EVENT_WRAPPER_PID"
EVENT_MONITOR_RC=$?
set -e
if [[ $EVENT_MONITOR_RC -eq 0 || $EVENT_MONITOR_RC -eq 124 ]] ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]] ||
   find "$TEST_TMP" -maxdepth 1 -type f -name "acore.$FIXTURE_PID.*" | grep -q .; then
    echo "lost event child identity continued, timed out, retained ptrace, or published" >&2
    exit 1
fi
grep -q "read auto-attached child from event.*failed" "$TEST_TMP/event-identity.log"
kill -TERM "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID"
EVENT_TARGET_RC=$?
set -e
if [[ $EVENT_TARGET_RC -ne 143 ]]; then
    echo "event identity failure changed target termination status $EVENT_TARGET_RC" >&2
    exit 1
fi
fi

# On monitor shutdown an event-zero SEIZE status is a real delivery stop. A
# GETSIGINFO failure must not turn DETACH(signal) into DETACH(0) and suppress
# an application-visible signal.
if [[ $CASE == detach-relay-error || $CASE == all ]]; then
CASE_RAN=1
start_fixture relay-term
ARTHUR_FAIL_GETSIGINFO=1 LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/detach-relay-error.acore" \
    >"$TEST_TMP/detach-relay-error.log" 2>&1 &
DETACH_RELAY_MONITOR_PID=$!
TARGET_PIDS+=("$DETACH_RELAY_MONITOR_PID")
wait_for_log "$TEST_TMP/detach-relay-error.log" "Launched in monitor mode"
kill -STOP "$DETACH_RELAY_MONITOR_PID"
for _ in $(seq 1 200); do
    [[ $(awk '{print $3}' "/proc/$DETACH_RELAY_MONITOR_PID/stat") == T ]] && break
    sleep 0.01
done
kill -TERM "$FIXTURE_PID"
for _ in $(seq 1 200); do
    [[ $(awk '{print $3}' "/proc/$FIXTURE_PID/stat") == t ]] && break
    sleep 0.01
done
if [[ $(awk '{print $3}' "/proc/$FIXTURE_PID/stat") != t ]]; then
    echo "target did not enter a signal-delivery ptrace stop" >&2
    exit 1
fi
kill -TERM "$DETACH_RELAY_MONITOR_PID"
kill -CONT "$DETACH_RELAY_MONITOR_PID"
expect_status 0 wait "$DETACH_RELAY_MONITOR_PID"
wait_for_process_exit "$FIXTURE_PID"
expect_status 42 wait "$FIXTURE_PID"
if [[ -e "$TEST_TMP/detach-relay-error.acore" ]]; then
    echo "monitor shutdown after delivery stop retained an acore" >&2
    exit 1
fi
fi

# A real waitpid error after the snapshot child is gone leaves the leader's
# stop identity unknown. Arthur must skip remote waitpid injection, restore the
# monitor options, reject publication, and end monitor service.
if [[ $CASE == final-wait-error || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory-spin 8
(
    cd "$TEST_TMP"
    exec timeout 20s env ARTHUR_FAIL_WAITPID_AFTER_CHILD_KILL=1 \
        LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
        "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
        -o "$TEST_TMP/final-wait-error-seed.acore"
) >"$TEST_TMP/final-wait-error.log" 2>&1 &
FINAL_WAIT_WRAPPER_PID=$!
TARGET_PIDS+=("$FINAL_WAIT_WRAPPER_PID")
wait_for_log "$TEST_TMP/final-wait-error.log" "Launched in monitor mode"
FINAL_WAIT_MONITOR_PID=$(find_timeout_child "$FINAL_WAIT_WRAPPER_PID")
kill -USR1 "$FINAL_WAIT_MONITOR_PID"
set +e
wait "$FINAL_WAIT_WRAPPER_PID"
FINAL_WAIT_RC=$?
set -e
if [[ $FINAL_WAIT_RC -eq 0 || $FINAL_WAIT_RC -eq 124 ]] ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]] ||
   find "$TEST_TMP" -maxdepth 1 -type f -name "acore.$FIXTURE_PID.*" | grep -q .; then
    echo "final wait error continued, timed out, retained ptrace, or published" >&2
    exit 1
fi
grep -q "wait for leader.*after snapshot failed" "$TEST_TMP/final-wait-error.log"
grep -q "wait status unavailable; skipping waitpid injection" \
    "$TEST_TMP/final-wait-error.log"
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
fi

# A clone PID becomes owned as soon as GETEVENTMSG succeeds. If its initial
# wait fails, cleanup must still detach that PID rather than only the creator.
if [[ $CASE == clone-wait-error || $CASE == all ]]; then
CASE_RAN=1
start_fixture clone-process-crash
timeout 10s env ARTHUR_FAIL_CLONE_CHILD_WAIT=1 \
    LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/clone-wait-error.acore" \
    >"$TEST_TMP/clone-wait-error.log" 2>&1 &
CLONE_WAIT_WRAPPER_PID=$!
TARGET_PIDS+=("$CLONE_WAIT_WRAPPER_PID")
wait_for_log "$TEST_TMP/clone-wait-error.log" "Launched in monitor mode"
kill -USR2 "$FIXTURE_PID"
wait_for_log "$TEST_TMP/clone-wait-error.log" "injected clone-child wait failure"
set +e
wait "$CLONE_WAIT_WRAPPER_PID"
CLONE_WAIT_RC=$?
set -e
if [[ $CLONE_WAIT_RC -eq 0 || $CLONE_WAIT_RC -eq 124 ]] ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]]; then
    echo "clone child wait failure continued, timed out, or retained target" >&2
    exit 1
fi
grep -q "detaching tracked clone child" "$TEST_TMP/clone-wait-error.log"
kill -TERM "$FIXTURE_PID"
expect_status 143 wait "$FIXTURE_PID"
fi

# The late-thread fixture creates a worker only after another TID enters a
# ptrace stop. This forces TRACECLONE into collect_threads; losing its event PID
# must set the monitor recovery gate and reject the snapshot.
if [[ $CASE == collect-event-error || $CASE == all ]]; then
CASE_RAN=1
start_fixture late-thread
(
    cd "$TEST_TMP"
    exec timeout 15s env ARTHUR_FAIL_GETEVENTMSG_AFTER_INTERRUPT=1 \
        LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
        "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
        -o "$TEST_TMP/collect-event-error-seed.acore"
) >"$TEST_TMP/collect-event-error.log" 2>&1 &
COLLECT_EVENT_WRAPPER_PID=$!
TARGET_PIDS+=("$COLLECT_EVENT_WRAPPER_PID")
wait_for_log "$TEST_TMP/collect-event-error.log" "Launched in monitor mode"
COLLECT_EVENT_MONITOR_PID=$(find_timeout_child "$COLLECT_EVENT_WRAPPER_PID")
kill -USR1 "$COLLECT_EVENT_MONITOR_PID"
set +e
wait "$COLLECT_EVENT_WRAPPER_PID"
COLLECT_EVENT_RC=$?
set -e
if [[ $COLLECT_EVENT_RC -eq 0 || $COLLECT_EVENT_RC -eq 124 ]] ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]] ||
   find "$TEST_TMP" -maxdepth 1 -type f -name "acore.$FIXTURE_PID.*" | grep -q .; then
    echo "collect clone event failure continued, timed out, retained ptrace, or published" >&2
    exit 1
fi
grep -q "cannot read clone event while stopping thread" \
    "$TEST_TMP/collect-event-error.log"
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
fi

# A successful attach/detach must not synthesize SIGCONT. Applications can
# install a SIGCONT handler or intentionally remain job-control stopped.
if [[ $CASE == detach || $CASE == all ]]; then
CASE_RAN=1
start_fixture relay-cont
expect_status 0 "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/detach.acore"
sleep 0.1
if [[ ! -r /proc/$FIXTURE_PID/stat ||
      $(awk '{print $3}' "/proc/$FIXTURE_PID/stat") == Z ]]; then
    set +e
    wait "$FIXTURE_PID"
    TARGET_RC=$?
    set -e
    echo "capture injected SIGCONT into target (status=$TARGET_RC)" >&2
    exit 1
fi
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/detach.acore" \
    -o "$TEST_TMP/detach.core"
"$TEST_TMP/core_note_test" "$TEST_TMP/detach.core" \
    "$(id -u)" "$(id -g)" 0 0x600 1 0 19
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
fi

# A real signal-delivery stop can race ahead of PTRACE_ATTACH's synthetic
# SIGSTOP. Arthur must preserve that signal and re-inject it when detaching.
if [[ $CASE == attach-relay || $CASE == all ]]; then
CASE_RAN=1
start_fixture relay-term
expect_status 0 env ARTHUR_ATTACH_DELIVERY_SIGNAL=15 \
    LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/attach-relay.acore"
wait_for_process_exit "$FIXTURE_PID"
expect_status 42 wait "$FIXTURE_PID"
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/attach-relay.acore" \
    -o "$TEST_TMP/attach-relay.core"
"$TEST_TMP/core_note_test" "$TEST_TMP/attach-relay.core" \
    "$(id -u)" "$(id -g)" 0 0x600 1 0 15
fi

# A transient DETACH failure is retried. A persistent failure must prevent
# atomic publication instead of reporting success while restoration is unknown.
if [[ $CASE == detach-failure || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory 8
printf 'existing-detach-output\n' >"$TEST_TMP/detach-failure.acore"
cp "$TEST_TMP/detach-failure.acore" "$TEST_TMP/detach-failure.expected"
set +e
ARTHUR_FAIL_DETACH=always LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/detach-failure.acore" \
    >"$TEST_TMP/detach-failure.log" 2>&1
DETACH_FAILURE_RC=$?
set -e
if [[ $DETACH_FAILURE_RC -eq 0 ]] ||
   ! cmp -s "$TEST_TMP/detach-failure.expected" \
       "$TEST_TMP/detach-failure.acore" ||
   find "$TEST_TMP" -maxdepth 1 \
       -name 'detach-failure.acore.tmp.*' | grep -q .; then
    echo "persistent detach failure succeeded, replaced output, or leaked a temporary" >&2
    exit 1
fi

grep -q "failed to restore every captured thread" "$TEST_TMP/detach-failure.log"
kill -KILL "$FIXTURE_PID" 2>/dev/null || true
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e

start_fixture memory 8
expect_status 0 env ARTHUR_FAIL_DETACH=once \
    LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/detach-retry.acore"
if ! kill -0 "$FIXTURE_PID" 2>/dev/null ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]]; then
    echo "transient detach retry did not restore the target" >&2
    exit 1
fi
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/detach-retry.acore" \
    -o "$TEST_TMP/detach-retry.core"
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
fi

# Register restoration and monitor-resume operations are part of snapshot
# success. Their failure must leave prior output untouched and publish no dump.
if [[ $CASE == restore-failure || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory-spin 8
printf 'existing-restore-output\n' >"$TEST_TMP/restore-failure.acore"
cp "$TEST_TMP/restore-failure.acore" "$TEST_TMP/restore-failure.expected"
set +e
ARTHUR_FAIL_SETREGS_FROM=4 LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -0 \
    -o "$TEST_TMP/restore-failure.acore" \
    >"$TEST_TMP/restore-failure.log" 2>&1
RESTORE_RC=$?
set -e
if [[ $RESTORE_RC -eq 0 || $RESTORE_RC -eq 124 ]] ||
   ! cmp -s "$TEST_TMP/restore-failure.expected" \
       "$TEST_TMP/restore-failure.acore"; then
    echo "failed GPR restoration succeeded, hung, or replaced prior output" >&2
    exit 1
fi
grep -q "restore registers.*after fork injection failed" \
    "$TEST_TMP/restore-failure.log"
kill -KILL "$FIXTURE_PID" 2>/dev/null || true
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e

for failure_spec in \
    ARTHUR_FAIL_GETREGS_AFTER_CHILD_KILL=1 \
    ARTHUR_FAIL_CLEAR_TRACEFORK=1 \
    ARTHUR_FAIL_CONT_AFTER_SETREGS=4; do
    failure_tag=${failure_spec%%=*}
    start_fixture memory-spin 8
    (
        cd "$TEST_TMP"
        exec timeout 20s env "$failure_spec" \
            LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
            "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
            -o "$TEST_TMP/$failure_tag-seed.acore"
    ) >"$TEST_TMP/$failure_tag.log" 2>&1 &
    MONITOR_PID=$!
    TARGET_PIDS+=("$MONITOR_PID")
    wait_for_log "$TEST_TMP/$failure_tag.log" "Launched in monitor mode"
    ARTHUR_MONITOR_PID=
    for _ in $(seq 1 100); do
        ARTHUR_MONITOR_PID=$(pgrep -P "$MONITOR_PID" | head -n 1 || true)
        if [[ -n $ARTHUR_MONITOR_PID ]]; then
            break
        fi
        sleep 0.01
    done
    if [[ -z $ARTHUR_MONITOR_PID ]]; then
        echo "cannot find injected monitor child for $failure_tag" >&2
        exit 1
    fi
    kill -USR1 "$ARTHUR_MONITOR_PID"
    set +e
    wait "$MONITOR_PID"
    MONITOR_RC=$?
    set -e
    if [[ $MONITOR_RC -eq 0 || $MONITOR_RC -eq 124 ]] ||
       find "$TEST_TMP" -maxdepth 1 -type f \
           -name "acore.$FIXTURE_PID.*" | grep -q . ||
       ! kill -0 "$FIXTURE_PID" 2>/dev/null ||
       [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]]; then
        echo "$failure_tag published a snapshot, hung, or failed to release target" >&2
        exit 1
    fi
    kill -KILL "$FIXTURE_PID"
    set +e
    wait "$FIXTURE_PID" 2>/dev/null
    set -e
done
fi

# Signals arriving in one of mode-0's remote-call windows must be delivered
# after Arthur restores the application state. The handler exits 42.
if [[ $CASE == mode0-relay || $CASE == all ]]; then
CASE_RAN=1
start_fixture relay-term
timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -0 \
    -o "$TEST_TMP/mode0.acore" >"$TEST_TMP/mode0.log" 2>&1 &
DUMPER_PID=$!
TARGET_PIDS+=("$DUMPER_PID")
wait_for_tracer "$FIXTURE_PID"
kill -TERM "$FIXTURE_PID"
set +e
wait "$DUMPER_PID"
DUMP_RC=$?
set -e
wait_for_process_exit "$FIXTURE_PID"
expect_status 42 wait "$FIXTURE_PID"
if [[ $DUMP_RC -eq 124 ]]; then
    echo "mode-0 dump timed out after relaying SIGTERM" >&2
    exit 1
fi
fi

# Static targets have no dynamic libc mmap/munmap/waitpid symbols. Mode 0 and
# monitored SIGUSR1 snapshots must use the already-stopped parent directly.
if [[ $CASE == static-fallback || $CASE == all ]]; then
CASE_RAN=1
"$TEST_TMP/static_target" >"$TEST_TMP/static-target.log" 2>&1 &
STATIC_PID=$!
TARGET_PIDS+=("$STATIC_PID")
wait_for_log "$TEST_TMP/static-target.log" ready

expect_status 0 timeout 20s "$ARTHUR_BIN" -p "$STATIC_PID" -0 \
    -o "$TEST_TMP/static.acore"
if ! kill -0 "$STATIC_PID" 2>/dev/null ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$STATIC_PID/status") != 0 ]]; then
    echo "mode-0 static fallback did not restore its target" >&2
    exit 1
fi
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/static.acore" \
    -o "$TEST_TMP/static.core"
LC_ALL=C readelf -h "$TEST_TMP/static.core" >"$TEST_TMP/static-readelf.log"
grep -q 'Type:.*CORE' "$TEST_TMP/static-readelf.log"

timeout 20s "$ARTHUR_BIN" -p "$STATIC_PID" -3 \
    -o "$TEST_TMP/static-monitor-seed.acore" \
    >"$TEST_TMP/static-monitor.log" 2>&1 &
STATIC_MONITOR_WRAPPER=$!
TARGET_PIDS+=("$STATIC_MONITOR_WRAPPER")
wait_for_log "$TEST_TMP/static-monitor.log" "Launched in monitor mode"
STATIC_MONITOR_PID=$(find_timeout_child "$STATIC_MONITOR_WRAPPER")
kill -USR1 "$STATIC_MONITOR_PID"
wait_for_log "$TEST_TMP/static-monitor.log" "writing out acore finished"
STATIC_SNAPSHOT=$(find "$TEST_TMP" -maxdepth 1 -type f \
    -name "acore.$STATIC_PID.*" -print -quit)
if [[ -z $STATIC_SNAPSHOT ]] ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$STATIC_PID/status") != \
      "$STATIC_MONITOR_PID" ]]; then
    echo "monitor static fallback did not publish or retain monitor ownership" >&2
    exit 1
fi
expect_status 0 "$ARTHUR_BIN" -c "$STATIC_SNAPSHOT" \
    -o "$TEST_TMP/static-monitor.core"
LC_ALL=C readelf -h "$TEST_TMP/static-monitor.core" \
    >"$TEST_TMP/static-monitor-readelf.log"
grep -q 'Type:.*CORE' "$TEST_TMP/static-monitor-readelf.log"
kill -TERM "$STATIC_PID"
expect_status 143 wait "$STATIC_PID"
expect_status 0 wait "$STATIC_MONITOR_WRAPPER"
fi

# MADV_DONTFORK mappings are absent from the COW child. Mode 0 must capture
# their parent bytes through its direct fallback instead of publishing zeros.
if [[ $CASE == dontfork || $CASE == all ]]; then
CASE_RAN=1
start_fixture dontfork-spin
expect_status 0 timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -0 \
    -o "$TEST_TMP/dontfork.acore"
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/dontfork.acore" \
    -o "$TEST_TMP/dontfork.core"
DONTFORK_ADDRESS=$(sed -n 's/^dontfork-address=//p' \
    "$TEST_TMP/fixture.log" | tail -n 1)
gdb -q -nx -batch -ex "x/gx $DONTFORK_ADDRESS" "$TEST_TMP/fixture" \
    "$TEST_TMP/dontfork.core" >"$TEST_TMP/dontfork-gdb.log" 2>&1
if ! grep -q '0x1122334455667788' "$TEST_TMP/dontfork-gdb.log"; then
    echo "mode-0 core lost a readable MADV_DONTFORK mapping" >&2
    cat "$TEST_TMP/dontfork-gdb.log" >&2
    exit 1
fi

(
    cd "$TEST_TMP"
    exec "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
        -o "$TEST_TMP/dontfork-monitor-seed.acore"
) >"$TEST_TMP/dontfork-monitor.log" 2>&1 &
MONITOR_PID=$!
TARGET_PIDS+=("$MONITOR_PID")
wait_for_log "$TEST_TMP/dontfork-monitor.log" "Launched in monitor mode"
kill -USR1 "$MONITOR_PID"
wait_for_log "$TEST_TMP/dontfork-monitor.log" "writing out acore finished"
MONITOR_SNAPSHOT=$(find "$TEST_TMP" -maxdepth 1 -type f \
    -name "acore.$FIXTURE_PID.*" -print -quit)
if [[ -z $MONITOR_SNAPSHOT ]]; then
    echo "monitor did not publish the MADV_DONTFORK snapshot" >&2
    exit 1
fi
expect_status 0 "$ARTHUR_BIN" -c "$MONITOR_SNAPSHOT" \
    -o "$TEST_TMP/dontfork-monitor.core"
gdb -q -nx -batch -ex "x/gx $DONTFORK_ADDRESS" "$TEST_TMP/fixture" \
    "$TEST_TMP/dontfork-monitor.core" \
    >"$TEST_TMP/dontfork-monitor-gdb.log" 2>&1
if ! grep -q '0x1122334455667788' "$TEST_TMP/dontfork-monitor-gdb.log"; then
    echo "monitor snapshot lost a readable MADV_DONTFORK mapping" >&2
    cat "$TEST_TMP/dontfork-monitor-gdb.log" >&2
    exit 1
fi
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
wait "$MONITOR_PID" 2>/dev/null
set -e
fi

# A MAP_SHARED page remains live in the fork child. The direct fallback must
# capture it at the same stop point as private memory instead of mixing times.
if [[ $CASE == shared || $CASE == all ]]; then
CASE_RAN=1
start_fixture shared-spin
expect_status 0 timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -0 \
    -o "$TEST_TMP/shared.acore"
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/shared.acore" \
    -o "$TEST_TMP/shared.core"
SHARED_ADDRESS=$(sed -n 's/^shared-address=//p' \
    "$TEST_TMP/fixture.log" | tail -n 1)
LOCAL_ADDRESS=$(sed -n 's/^local-address=//p' \
    "$TEST_TMP/fixture.log" | tail -n 1)
gdb -q -nx -batch \
    -ex "printf \"CONSISTENCY %llu %llu %llu\\n\", *(unsigned long long*)$LOCAL_ADDRESS, *((unsigned long long*)$LOCAL_ADDRESS + 1), *(unsigned long long*)$SHARED_ADDRESS" \
    "$TEST_TMP/fixture" "$TEST_TMP/shared.core" \
    >"$TEST_TMP/shared-gdb.log" 2>&1
read -r _ snapshot_seq local_value shared_value < <(
    grep '^CONSISTENCY ' "$TEST_TMP/shared-gdb.log"
)
if (( snapshot_seq % 2 != 0 || local_value != shared_value )); then
    echo "mode-0 core mixed private and MAP_SHARED memory from different times" >&2
    cat "$TEST_TMP/shared-gdb.log" >&2
    exit 1
fi
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
fi

# Threads created while the initial /proc/task enumeration is being stopped
# must be discovered by a later convergence pass and receive register notes.
if [[ $CASE == late-thread || $CASE == all ]]; then
CASE_RAN=1
start_fixture late-thread
expect_status 0 timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/late-thread.acore"
wait_for_log "$TEST_TMP/fixture.log" "late-tid="
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/late-thread.acore" \
    -o "$TEST_TMP/late-thread.core"
LATE_TID=$(sed -n 's/^late-tid=//p' "$TEST_TMP/fixture.log" | tail -n 1)
gdb -q -nx -batch -ex 'info threads' "$TEST_TMP/fixture" \
    "$TEST_TMP/late-thread.core" >"$TEST_TMP/late-thread-gdb.log" 2>&1
if ! grep -Eq "LWP ${LATE_TID}([ )]|$)" "$TEST_TMP/late-thread-gdb.log"; then
    echo "one-shot thread enumeration omitted a thread created during attach" >&2
    cat "$TEST_TMP/late-thread-gdb.log" >&2
    exit 1
fi
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
fi

# Non-readable VMAs still belong to the address space. They need a zero-file
# PT_LOAD so offline tools retain their address, size, and protection flags.
if [[ $CASE == prot-none || $CASE == all ]]; then
CASE_RAN=1
start_fixture prot-none
expect_status 0 "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/prot-none.acore"
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/prot-none.acore" \
    -o "$TEST_TMP/prot-none.core"
PROT_NONE_ADDRESS=$(sed -n 's/^prot-none-address=//p' \
    "$TEST_TMP/fixture.log" | tail -n 1)
PROT_NONE_HEX=${PROT_NONE_ADDRESS#0x}
readelf -lW "$TEST_TMP/prot-none.core" >"$TEST_TMP/prot-none-readelf.log"
if ! grep -Eiq "LOAD +0x[0-9a-f]+ +0x0*${PROT_NONE_HEX} .* 0x0+ +0x0*1000 " \
    "$TEST_TMP/prot-none-readelf.log"; then
    echo "core omitted the mapped PROT_NONE region" >&2
    cat "$TEST_TMP/prot-none-readelf.log" >&2
    exit 1
fi
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
fi

# PROT_WRITE without PROT_READ is still a readable memory source through
# /proc/<pid>/mem and must not be represented as a false zero-filled LOAD.
if [[ $CASE == write-only || $CASE == all ]]; then
CASE_RAN=1
start_fixture write-only
expect_status 0 "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/write-only.acore"
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/write-only.acore" \
    -o "$TEST_TMP/write-only.core"
WRITE_ONLY_ADDRESS=$(sed -n 's/^write-only-address=//p' \
    "$TEST_TMP/fixture.log" | tail -n 1)
gdb -q -nx -batch -ex "x/gx $WRITE_ONLY_ADDRESS" "$TEST_TMP/fixture" \
    "$TEST_TMP/write-only.core" >"$TEST_TMP/write-only-gdb.log" 2>&1
if ! grep -qi '0x8877665544332211' "$TEST_TMP/write-only-gdb.log"; then
    echo "write-only LOAD lost its runtime bytes" >&2
    cat "$TEST_TMP/write-only-gdb.log" >&2
    exit 1
fi
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e

# A write-only DONTFORK mapping has captured bytes even though it lacks PF_R.
# Mode 0 must detect its VmFlags and use the stopped parent as the source.
start_fixture write-only-dontfork-spin
expect_status 0 timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -0 \
    -o "$TEST_TMP/write-only-dontfork.acore"
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/write-only-dontfork.acore" \
    -o "$TEST_TMP/write-only-dontfork.core"
WRITE_ONLY_DONTFORK_ADDRESS=$(sed -n 's/^write-only-dontfork-address=//p' \
    "$TEST_TMP/fixture.log" | tail -n 1)
gdb -q -nx -batch -ex "x/gx $WRITE_ONLY_DONTFORK_ADDRESS" \
    "$TEST_TMP/fixture" "$TEST_TMP/write-only-dontfork.core" \
    >"$TEST_TMP/write-only-dontfork-gdb.log" 2>&1
if ! grep -qi '0x1029384756abcdef' "$TEST_TMP/write-only-dontfork-gdb.log"; then
    echo "mode-0 core lost a write-only MADV_DONTFORK mapping" >&2
    cat "$TEST_TMP/write-only-dontfork-gdb.log" >&2
    exit 1
fi
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
fi

# Runtime-private changes in executable file mappings are not recoverable from
# the backing file. Preserve bytes beyond the first page as part of the core.
if [[ $CASE == rwx-file || $CASE == all ]]; then
CASE_RAN=1
start_fixture rwx-file "$TEST_TMP/rwx-backing.bin"
expect_status 0 "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/rwx-file.acore"
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/rwx-file.acore" \
    -o "$TEST_TMP/rwx-file.core"
RWX_FILE_ADDRESS=$(sed -n 's/^rwx-file-address=//p' \
    "$TEST_TMP/fixture.log" | tail -n 1)
gdb -q -nx -batch -ex "x/gx $RWX_FILE_ADDRESS" "$TEST_TMP/fixture" \
    "$TEST_TMP/rwx-file.core" >"$TEST_TMP/rwx-file-gdb.log" 2>&1
if ! grep -qi '0xa1b2c3d4e5f60718' "$TEST_TMP/rwx-file-gdb.log"; then
    echo "executable file LOAD lost a private modification after page one" >&2
    cat "$TEST_TMP/rwx-file-gdb.log" >&2
    exit 1
fi
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
fi

# A thread created after monitor startup must remain traced and produce a core
# when it crashes. This is the production worker-thread failure mode.
if [[ $CASE == worker || $CASE == all ]]; then
CASE_RAN=1
start_fixture worker-crash
timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/worker.acore" >"$TEST_TMP/worker-monitor.log" 2>&1 &
MONITOR_PID=$!
TARGET_PIDS+=("$MONITOR_PID")
wait_for_log "$TEST_TMP/worker-monitor.log" "Launched in monitor mode"
kill -USR2 "$FIXTURE_PID"
wait_for_log "$TEST_TMP/fixture.log" "worker-tid="
expect_status 0 wait "$MONITOR_PID"
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/worker.acore" \
    -o "$TEST_TMP/worker.core"
if [[ $(readelf -n "$TEST_TMP/worker.core" | grep -c 'NT_PRSTATUS') -lt 2 ]]; then
    echo "worker crash core does not contain both thread states" >&2
    exit 1
fi
WORKER_TID=$(sed -n 's/^worker-tid=//p' "$TEST_TMP/fixture.log" | tail -n 1)
gdb -q -nx -batch -ex 'info threads' "$TEST_TMP/fixture" \
    "$TEST_TMP/worker.core" >"$TEST_TMP/worker-gdb.log" 2>&1
if ! grep -Eq "^\\*.*LWP ${WORKER_TID}([ )]|$)" "$TEST_TMP/worker-gdb.log"; then
    echo "worker crash core did not select crashing LWP $WORKER_TID by default" >&2
    cat "$TEST_TMP/worker-gdb.log" >&2
    exit 1
fi
"$TEST_TMP/core_note_test" "$TEST_TMP/worker.core" \
    "$(id -u)" "$(id -g)" 0x600 0 1 11 11
fi

# A Linux process can outlive its original thread-group leader when main calls
# pthread_exit. Snapshots and a later worker crash must not require leader regs.
if [[ $CASE == leader-exit || $CASE == all ]]; then
CASE_RAN=1
start_fixture leader-exit
timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/leader-exit.acore" \
    >"$TEST_TMP/leader-exit-monitor.log" 2>&1 &
LEADER_MONITOR_WRAPPER=$!
TARGET_PIDS+=("$LEADER_MONITOR_WRAPPER")
wait_for_log "$TEST_TMP/leader-exit-monitor.log" "Launched in monitor mode"
LEADER_MONITOR_PID=$(find_timeout_child "$LEADER_MONITOR_WRAPPER")
wait_for_log "$TEST_TMP/fixture.log" "leader-worker-tid="
LEADER_WORKER_TID=$(sed -n 's/^leader-worker-tid=//p' \
    "$TEST_TMP/fixture.log" | tail -n 1)
kill -USR2 "$FIXTURE_PID"
LEADER_EXITED=0
for _ in $(seq 1 200); do
    LEADER_STATE=$(awk '{print $3}' \
        "/proc/$FIXTURE_PID/task/$FIXTURE_PID/stat" 2>/dev/null || true)
    if [[ $LEADER_STATE == Z ]]; then
        LEADER_EXITED=1
        break
    fi
    sleep 0.01
done
if [[ $LEADER_EXITED -ne 1 ]]; then
    echo "fixture leader did not enter its legal post-pthread_exit zombie state" >&2
    exit 1
fi

# Job-control applies to the surviving thread group even though the original
# leader can no longer report a stop. A SIGUSR1 request while the worker is
# group-stopped must be skipped rather than resuming it as a side effect of the
# direct snapshot path.
kill -STOP "$FIXTURE_PID"
for _ in $(seq 1 200); do
    LEADER_WORKER_STATE=$(awk '{print $3}' \
        "/proc/$LEADER_WORKER_TID/stat" 2>/dev/null || true)
    if [[ $LEADER_WORKER_STATE == T || $LEADER_WORKER_STATE == t ]]; then
        break
    fi
    sleep 0.01
done
if [[ $LEADER_WORKER_STATE != T && $LEADER_WORKER_STATE != t ]]; then
    echo "post-leader-exit worker did not enter group-stop" >&2
    exit 1
fi
kill -USR1 "$LEADER_MONITOR_PID"
wait_for_log "$TEST_TMP/leader-exit-monitor.log" \
    "group-stop; skipping SIGUSR1 dump"
if find "$TEST_TMP" -maxdepth 1 -type f \
       -name "acore.$FIXTURE_PID.*" | grep -q . ||
   ! [[ $(awk '{print $3}' "/proc/$LEADER_WORKER_TID/stat") =~ ^[Tt]$ ]]; then
    echo "post-leader-exit group-stop was lost during SIGUSR1 request" >&2
    exit 1
fi
kill -CONT "$FIXTURE_PID"
for _ in $(seq 1 200); do
    LEADER_WORKER_STATE=$(awk '{print $3}' \
        "/proc/$LEADER_WORKER_TID/stat" 2>/dev/null || true)
    if [[ ! $LEADER_WORKER_STATE =~ ^[Tt]$ && -n $LEADER_WORKER_STATE ]]; then
        break
    fi
    sleep 0.01
done
if [[ $LEADER_WORKER_STATE =~ ^[Tt]$ || -z $LEADER_WORKER_STATE ]]; then
    echo "post-leader-exit worker did not resume after SIGCONT" >&2
    exit 1
fi

kill -USR1 "$LEADER_MONITOR_PID"
wait_for_log "$TEST_TMP/leader-exit-monitor.log" "writing out acore finished"
LEADER_SNAPSHOT=$(find "$TEST_TMP" -maxdepth 1 -type f \
    -name "acore.$FIXTURE_PID.*" -print -quit)
if [[ -z $LEADER_SNAPSHOT ]] ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$LEADER_WORKER_TID/status") != \
      "$LEADER_MONITOR_PID" ]]; then
    echo "post-leader-exit snapshot failed or lost worker ownership" >&2
    exit 1
fi
expect_status 0 "$ARTHUR_BIN" -c "$LEADER_SNAPSHOT" \
    -o "$TEST_TMP/leader-snapshot.core"

# A completed direct snapshot must leave every worker reusable for another
# request, and the monitor sequence must allocate a distinct name even within
# the same second.
LEADER_SNAPSHOT_COUNT=$(find "$TEST_TMP" -maxdepth 1 -type f \
    -name "acore.$FIXTURE_PID.*" ! -name '*.tmp.*' | wc -l)
kill -USR1 "$LEADER_MONITOR_PID"
for _ in $(seq 1 400); do
    LEADER_SNAPSHOT_COUNT_AFTER=$(find "$TEST_TMP" -maxdepth 1 -type f \
        -name "acore.$FIXTURE_PID.*" ! -name '*.tmp.*' | wc -l)
    if [[ $LEADER_SNAPSHOT_COUNT_AFTER -gt $LEADER_SNAPSHOT_COUNT ]]; then
        break
    fi
    sleep 0.025
done
if [[ $LEADER_SNAPSHOT_COUNT_AFTER -ne $((LEADER_SNAPSHOT_COUNT + 1)) ]] ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$LEADER_WORKER_TID/status") != \
      "$LEADER_MONITOR_PID" ]]; then
    echo "repeated post-leader-exit snapshot failed or lost worker ownership" >&2
    exit 1
fi
LEADER_SNAPSHOT_2=$(find "$TEST_TMP" -maxdepth 1 -type f \
    -name "acore.$FIXTURE_PID.*" ! -name '*.tmp.*' | sort | tail -n 1)
expect_status 0 "$ARTHUR_BIN" -c "$LEADER_SNAPSHOT_2" \
    -o "$TEST_TMP/leader-snapshot-2.core"

kill -SEGV "$FIXTURE_PID"
expect_status 0 wait "$LEADER_MONITOR_WRAPPER"
expect_status 139 wait "$FIXTURE_PID"
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/leader-exit.acore" \
    -o "$TEST_TMP/leader-exit.core"
gdb -q -nx -batch -ex 'info threads' "$TEST_TMP/fixture" \
    "$TEST_TMP/leader-exit.core" >"$TEST_TMP/leader-exit-gdb.log" 2>&1
if ! grep -Eq "^\\*.*LWP ${LEADER_WORKER_TID}([ )]|$)" \
    "$TEST_TMP/leader-exit-gdb.log"; then
    echo "post-leader-exit core did not select crashing worker $LEADER_WORKER_TID" >&2
    cat "$TEST_TMP/leader-exit-gdb.log" >&2
    exit 1
fi

# A non-core terminating signal after pthread_exit is an ordinary lifecycle
# end: monitor must release ownership, remove its seed output, and return 0.
start_fixture leader-exit
timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/leader-exit-term.acore" \
    >"$TEST_TMP/leader-exit-term-monitor.log" 2>&1 &
LEADER_TERM_WRAPPER=$!
TARGET_PIDS+=("$LEADER_TERM_WRAPPER")
wait_for_log "$TEST_TMP/leader-exit-term-monitor.log" "Launched in monitor mode"
wait_for_log "$TEST_TMP/fixture.log" "leader-worker-tid="
kill -USR2 "$FIXTURE_PID"
for _ in $(seq 1 200); do
    LEADER_STATE=$(awk '{print $3}' \
        "/proc/$FIXTURE_PID/task/$FIXTURE_PID/stat" 2>/dev/null || true)
    if [[ $LEADER_STATE == Z ]]; then
        break
    fi
    sleep 0.01
done
if [[ $LEADER_STATE != Z ]]; then
    echo "second fixture leader did not exit" >&2
    exit 1
fi
kill -TERM "$FIXTURE_PID"
expect_status 143 wait "$FIXTURE_PID"
expect_status 0 wait "$LEADER_TERM_WRAPPER"
if [[ -e "$TEST_TMP/leader-exit-term.acore" ]]; then
    echo "non-core termination after leader exit produced an acore" >&2
    exit 1
fi
fi

# A successful exec is a normal process lifecycle event, not a SIGTRAP crash.
# Monitor must follow the replacement image and continue tracing it.
if [[ $CASE == exec || $CASE == all ]]; then
CASE_RAN=1
start_fixture exec
timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/exec.acore" >"$TEST_TMP/exec-monitor.log" 2>&1 &
MONITOR_PID=$!
TARGET_PIDS+=("$MONITOR_PID")
wait_for_log "$TEST_TMP/exec-monitor.log" "Launched in monitor mode"
kill -USR2 "$FIXTURE_PID"
EXEC_SEEN=0
for _ in $(seq 1 200); do
    if [[ $(readlink "/proc/$FIXTURE_PID/exe" 2>/dev/null || true) == */sleep ]]; then
        EXEC_SEEN=1
        break
    fi
    if ! kill -0 "$FIXTURE_PID" 2>/dev/null ||
       ! kill -0 "$MONITOR_PID" 2>/dev/null; then
        break
    fi
    sleep 0.01
done
if [[ $EXEC_SEEN -ne 1 ]] || ! kill -0 "$MONITOR_PID" 2>/dev/null; then
    echo "monitor treated a successful exec as a fatal SIGTRAP" >&2
    exit 1
fi
kill -TERM "$FIXTURE_PID"
expect_status 143 wait "$FIXTURE_PID"
expect_status 0 wait "$MONITOR_PID"
if [[ -e "$TEST_TMP/exec.acore" ]]; then
    echo "normal exec produced a false crash acore" >&2
    exit 1
fi
fi

# PTRACE_EVENT_CLONE can describe an independent process (non-SIGCHLD exit
# signal), not only a pthread. Its crash must not be attributed to the parent.
if [[ $CASE == clone-process || $CASE == all ]]; then
CASE_RAN=1
start_fixture clone-process-crash
timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/clone-process.acore" \
    >"$TEST_TMP/clone-process-monitor.log" 2>&1 &
MONITOR_PID=$!
TARGET_PIDS+=("$MONITOR_PID")
wait_for_log "$TEST_TMP/clone-process-monitor.log" "Launched in monitor mode"
kill -USR2 "$FIXTURE_PID"
wait_for_log "$TEST_TMP/fixture.log" "clone-process-pid="
sleep 0.1
if ! kill -0 "$FIXTURE_PID" 2>/dev/null ||
   ! kill -0 "$MONITOR_PID" 2>/dev/null; then
    echo "monitor attributed an independent clone child's crash to its parent" >&2
    exit 1
fi
kill -TERM "$FIXTURE_PID"
expect_status 143 wait "$FIXTURE_PID"
expect_status 0 wait "$MONITOR_PID"
if [[ -e "$TEST_TMP/clone-process.acore" ]]; then
    echo "independent clone child produced a false parent crash acore" >&2
    exit 1
fi
fi

# SIGBUS is a core-dumping signal too. Monitor must capture it and preserve the
# kernel's default signal disposition after snapshotting.
if [[ $CASE == fatal || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory 8
timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/fatal.acore" >"$TEST_TMP/fatal-monitor.log" 2>&1 &
MONITOR_PID=$!
TARGET_PIDS+=("$MONITOR_PID")
wait_for_log "$TEST_TMP/fatal-monitor.log" "Launched in monitor mode"
kill -BUS "$FIXTURE_PID"
expect_status 135 wait "$FIXTURE_PID"
expect_status 0 wait "$MONITOR_PID"
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/fatal.acore" \
    -o "$TEST_TMP/fatal.core"
fi

# An explicitly ignored core-dumping signal is not a crash. Arthur must relay
# it and continue monitoring instead of writing a false core and exiting.
if [[ $CASE == ignored || $CASE == all ]]; then
CASE_RAN=1
start_fixture ignore-quit
timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/ignored.acore" >"$TEST_TMP/ignored-monitor.log" 2>&1 &
MONITOR_PID=$!
TARGET_PIDS+=("$MONITOR_PID")
wait_for_log "$TEST_TMP/ignored-monitor.log" "Launched in monitor mode"
kill -QUIT "$FIXTURE_PID"
sleep 0.1
if ! kill -0 "$FIXTURE_PID" 2>/dev/null || ! kill -0 "$MONITOR_PID" 2>/dev/null; then
    echo "ignored SIGQUIT was treated as a fatal crash" >&2
    exit 1
fi

kill -TERM "$FIXTURE_PID"
expect_status 143 wait "$FIXTURE_PID"
expect_status 0 wait "$MONITOR_PID"
if [[ -e "$TEST_TMP/ignored.acore" ]]; then
    echo "ignored SIGQUIT produced a false acore" >&2
    exit 1
fi
fi

# Linux force-delivers a synchronous hardware fault even if user space marked
# SIGSEGV ignored. At the ptrace stop the disposition is already default, so
# Arthur must capture it while still relaying ordinary ignored signals above.
if [[ $CASE == sync-ignored || $CASE == all ]]; then
CASE_RAN=1
start_fixture ignore-segv-sync
timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/sync-ignored.acore" >"$TEST_TMP/sync-ignored-monitor.log" 2>&1 &
MONITOR_PID=$!
TARGET_PIDS+=("$MONITOR_PID")
wait_for_log "$TEST_TMP/sync-ignored-monitor.log" "Launched in monitor mode"
kill -USR2 "$FIXTURE_PID"
expect_status 139 wait "$FIXTURE_PID"
expect_status 0 wait "$MONITOR_PID"
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/sync-ignored.acore" \
    -o "$TEST_TMP/sync-ignored.core"
fi

# A one-shot mode-1 capture must preserve an existing job-control stop. This
# covers detach signal 0 as well as the attach-generated SIGSTOP interaction.
if [[ $CASE == group-stop || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory 8
kill -STOP "$FIXTURE_PID"
for _ in $(seq 1 200); do
    if [[ $(awk '{print $3}' "/proc/$FIXTURE_PID/stat") == T ]]; then
        break
    fi
    sleep 0.01
done
if [[ $(awk '{print $3}' "/proc/$FIXTURE_PID/stat") != T ]]; then
    echo "fixture did not enter job-control stop" >&2
    exit 1
fi
expect_status 0 "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/group-stop.acore"
if [[ $(awk '{print $3}' "/proc/$FIXTURE_PID/stat") != T ]] ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]]; then
    echo "mode-1 capture changed the target's job-control or tracer state" >&2
    exit 1
fi
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/group-stop.acore" \
    -o "$TEST_TMP/group-stop.core"
kill -CONT "$FIXTURE_PID"
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
fi

# Ordinary delivery stops must be relayed to the original tracee TID. The
# handler exits 42; Arthur itself should observe normal process exit and return 0.
if [[ $CASE == relay || $CASE == all ]]; then
CASE_RAN=1
start_fixture relay-term
timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/relay.acore" >"$TEST_TMP/relay-monitor.log" 2>&1 &
MONITOR_PID=$!
TARGET_PIDS+=("$MONITOR_PID")
wait_for_log "$TEST_TMP/relay-monitor.log" "Launched in monitor mode"
kill -TERM "$FIXTURE_PID"
expect_status 42 wait "$FIXTURE_PID"
expect_status 0 wait "$MONITOR_PID"
if [[ -e "$TEST_TMP/relay.acore" ]]; then
    echo "monitor left an empty acore after normal target exit" >&2
    exit 1
fi
fi

# A normal SIGUSR1 request must still produce a valid, convertible snapshot
# while every target TID remains under persistent monitor ownership.
if [[ $CASE == snapshot || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory-spin 8
mkdir "$TEST_TMP/snapshot-cwd" "$TEST_TMP/snapshot-output"
(
    cd "$TEST_TMP/snapshot-cwd"
    exec timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
        -o "$TEST_TMP/snapshot-output/snapshot-seed.acore"
) >"$TEST_TMP/snapshot-monitor.log" 2>&1 &
MONITOR_PID=$!
TARGET_PIDS+=("$MONITOR_PID")
wait_for_log "$TEST_TMP/snapshot-monitor.log" "Launched in monitor mode"
ARTHUR_MONITOR_PID=
for _ in $(seq 1 100); do
    ARTHUR_MONITOR_PID=$(pgrep -P "$MONITOR_PID" | head -n 1 || true)
    if [[ -n $ARTHUR_MONITOR_PID ]]; then
        break
    fi
    sleep 0.01
done
if [[ -z $ARTHUR_MONITOR_PID ]]; then
    echo "cannot find monitor child under timeout" >&2
    exit 1
fi

kill -USR1 "$ARTHUR_MONITOR_PID"
wait_for_log "$TEST_TMP/snapshot-monitor.log" "writing out acore finished"
SNAPSHOT=$(find "$TEST_TMP/snapshot-output" -maxdepth 1 -type f \
    -name "acore.$FIXTURE_PID.*" -print -quit)
if [[ -z $SNAPSHOT ]]; then
    echo "SIGUSR1 monitor request did not produce an acore beside -o" >&2
    exit 1
fi
if find "$TEST_TMP/snapshot-cwd" -maxdepth 1 -type f \
    -name "acore.$FIXTURE_PID.*" | grep -q .; then
    echo "SIGUSR1 monitor request wrote its acore in the process cwd" >&2
    exit 1
fi
expect_status 0 "$ARTHUR_BIN" -c "$SNAPSHOT" -o "$TEST_TMP/snapshot.core"
kill -TERM "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID"
TARGET_RC=$?
set -e
if [[ $TARGET_RC -ne 143 ]]; then
    echo "snapshot target terminated with unexpected status $TARGET_RC" >&2
    exit 1
fi
expect_status 0 wait "$MONITOR_PID"
if [[ -e "$TEST_TMP/snapshot-output/snapshot-seed.acore" ]]; then
    echo "monitor left seed acore after target termination" >&2
    exit 1
fi
fi

# Snapshot sequence numbers restart with a new monitor. An existing automatic
# name from the same target/second must be preserved and skipped.
if [[ $CASE == snapshot-collision || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory-spin 8
mkdir "$TEST_TMP/snapshot-collision-output"
printf 'prior-snapshot-sentinel\n' \
    >"$TEST_TMP/snapshot-collision-output/acore.$FIXTURE_PID.1700000000.0"
timeout 20s env ARTHUR_FAKE_TIME=1700000000 \
    LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/snapshot-collision-output/seed.acore" \
    >"$TEST_TMP/snapshot-collision.log" 2>&1 &
COLLISION_WRAPPER=$!
TARGET_PIDS+=("$COLLISION_WRAPPER")
wait_for_log "$TEST_TMP/snapshot-collision.log" "Launched in monitor mode"
COLLISION_MONITOR=$(find_timeout_child "$COLLISION_WRAPPER")
kill -USR1 "$COLLISION_MONITOR"
wait_for_log "$TEST_TMP/snapshot-collision.log" "writing out acore finished"
if [[ $(<"$TEST_TMP/snapshot-collision-output/acore.$FIXTURE_PID.1700000000.0") != \
      "prior-snapshot-sentinel" ]] ||
   [[ ! -s "$TEST_TMP/snapshot-collision-output/acore.$FIXTURE_PID.1700000000.1" ]]; then
    echo "SIGUSR1 snapshot overwrote or failed to skip an existing automatic name" >&2
    exit 1
fi
expect_status 0 "$ARTHUR_BIN" \
    -c "$TEST_TMP/snapshot-collision-output/acore.$FIXTURE_PID.1700000000.1" \
    -o "$TEST_TMP/snapshot-collision.core"
kill -TERM "$FIXTURE_PID"
expect_status 143 wait "$FIXTURE_PID"
expect_status 0 wait "$COLLISION_WRAPPER"
fi

# A target fork observed during the TRACEFORK snapshot window must be detached
# without synthesizing SIGCONT in the newly created business process.
if [[ $CASE == fork-cont || $CASE == all ]]; then
CASE_RAN=1
start_fixture fork-cont
(
    cd "$TEST_TMP"
    exec timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
        -o "$TEST_TMP/fork-cont-seed.acore"
) >"$TEST_TMP/fork-cont-monitor.log" 2>&1 &
MONITOR_PID=$!
TARGET_PIDS+=("$MONITOR_PID")
wait_for_log "$TEST_TMP/fork-cont-monitor.log" "Launched in monitor mode"
ARTHUR_MONITOR_PID=
for _ in $(seq 1 100); do
    ARTHUR_MONITOR_PID=$(pgrep -P "$MONITOR_PID" | head -n 1 || true)
    if [[ -n $ARTHUR_MONITOR_PID ]]; then
        break
    fi
    sleep 0.01
done
if [[ -z $ARTHUR_MONITOR_PID ]]; then
    echo "cannot find fork-cont monitor child" >&2
    exit 1
fi
kill -USR1 "$ARTHUR_MONITOR_PID"
wait_for_log "$TEST_TMP/fork-cont-monitor.log" "writing out acore finished"
sleep 0.1
if grep -q '^child-sigcont$' "$TEST_TMP/fixture.log"; then
    echo "monitor snapshot injected SIGCONT into an auto-attached target child" >&2
    exit 1
fi
FORK_CONT_SNAPSHOT=$(find "$TEST_TMP" -maxdepth 1 -type f \
    -name "acore.$FIXTURE_PID.*" -print -quit)
if [[ -z $FORK_CONT_SNAPSHOT ]]; then
    echo "fork-cont monitor did not publish its snapshot" >&2
    exit 1
fi
expect_status 0 "$ARTHUR_BIN" -c "$FORK_CONT_SNAPSHOT" \
    -o "$TEST_TMP/fork-cont.core"
kill -TERM "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID"
TARGET_RC=$?
set -e
if [[ $TARGET_RC -ne 143 ]]; then
    echo "fork-cont target terminated with unexpected status $TARGET_RC" >&2
    exit 1
fi
expect_status 0 wait "$MONITOR_PID"
fi

# A real signal arriving while SIGUSR1 forkcore is stopping/restoring threads
# must remain waitable and be relayed after the snapshot attempt.
if [[ $CASE == race || $CASE == all ]]; then
CASE_RAN=1
start_fixture relay-term
(
    cd "$TEST_TMP"
    exec timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
        -o "$TEST_TMP/race.acore"
) >"$TEST_TMP/race-monitor.log" 2>&1 &
MONITOR_PID=$!
TARGET_PIDS+=("$MONITOR_PID")
wait_for_log "$TEST_TMP/race-monitor.log" "Launched in monitor mode"
ARTHUR_MONITOR_PID=
for _ in $(seq 1 100); do
    ARTHUR_MONITOR_PID=$(pgrep -P "$MONITOR_PID" | head -n 1 || true)
    if [[ -n $ARTHUR_MONITOR_PID ]]; then
        break
    fi
    sleep 0.01
done
if [[ -z $ARTHUR_MONITOR_PID ]]; then
    echo "cannot find monitor child under timeout" >&2
    exit 1
fi
kill -USR1 "$ARTHUR_MONITOR_PID"
sleep 0.005
kill -TERM "$FIXTURE_PID"
expect_status 42 wait "$FIXTURE_PID"
expect_status 0 wait "$MONITOR_PID"
if [[ -e "$TEST_TMP/race.acore" ]]; then
    echo "monitor left an empty acore after raced normal exit" >&2
    exit 1
fi
fi

# A disappearing /proc/<pid>/mem source is an error, not a successful zero core.
if [[ $CASE == vanish || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory 512
"$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/vanish.acore" >"$TEST_TMP/vanish.log" 2>&1 &
DUMPER_PID=$!
TARGET_PIDS+=("$DUMPER_PID")
for _ in $(seq 1 400); do
    partial=$(find "$TEST_TMP" -maxdepth 1 -type f \
        -name 'vanish.acore.tmp.*' -print -quit)
    size=$(stat -c %s "$partial" 2>/dev/null || echo 0)
    if [[ $size -gt 65536 ]]; then
        break
    fi
    if ! kill -0 "$DUMPER_PID" 2>/dev/null; then
        echo "dump finished before vanish fault could be injected" >&2
        exit 1
    fi
    sleep 0.01
done
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
wait "$DUMPER_PID"
DUMP_RC=$?
set -e
if [[ $DUMP_RC -eq 0 || -e "$TEST_TMP/vanish.acore" ]]; then
    echo "vanished target produced a successful or retained acore" >&2
    exit 1
fi
grep -q "refusing partial core\|no memory readable" "$TEST_TMP/vanish.log"
fi

# General registers are mandatory. FP state is optional, but an unavailable
# regset must be omitted instead of serialized as a valid all-zero note.
if [[ $CASE == register-failure || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory 8
printf 'existing-register-output\n' >"$TEST_TMP/register-failure.acore"
cp "$TEST_TMP/register-failure.acore" "$TEST_TMP/register-failure.expected"
set +e
ARTHUR_FAIL_GETREGS=1 LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/register-failure.acore" \
    >"$TEST_TMP/register-failure.log" 2>&1
REGISTER_RC=$?
set -e
if [[ $REGISTER_RC -eq 0 ]] ||
   ! cmp -s "$TEST_TMP/register-failure.expected" \
       "$TEST_TMP/register-failure.acore" ||
   ! kill -0 "$FIXTURE_PID" 2>/dev/null ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]]; then
    echo "failed GP register capture succeeded, replaced output, or froze target" >&2
    exit 1
fi
grep -q "refusing unusable thread metadata" "$TEST_TMP/register-failure.log"

expect_status 0 env ARTHUR_FAIL_GETFPREGS=1 \
    LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/fpreg-failure.acore"
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/fpreg-failure.acore" \
    -o "$TEST_TMP/fpreg-failure.core"
"$TEST_TMP/core_note_test" "$TEST_TMP/fpreg-failure.core" \
    "$(id -u)" "$(id -g)" 0 0x600 1 0 0 0 0

printf 'existing-siginfo-output\n' >"$TEST_TMP/siginfo-failure.acore"
cp "$TEST_TMP/siginfo-failure.acore" "$TEST_TMP/siginfo-failure.expected"
ARTHUR_FAIL_GETSIGINFO=1 LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
    -o "$TEST_TMP/siginfo-failure.acore" \
    >"$TEST_TMP/siginfo-failure.log" 2>&1 &
MONITOR_PID=$!
TARGET_PIDS+=("$MONITOR_PID")
wait_for_log "$TEST_TMP/siginfo-failure.log" "Launched in monitor mode"
kill -BUS "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID"
SIGINFO_TARGET_RC=$?
wait "$MONITOR_PID"
SIGINFO_MONITOR_RC=$?
set -e
if [[ $SIGINFO_TARGET_RC -ne 135 || $SIGINFO_MONITOR_RC -eq 0 ]] ||
   ! cmp -s "$TEST_TMP/siginfo-failure.expected" \
       "$TEST_TMP/siginfo-failure.acore" ||
   find "$TEST_TMP" -maxdepth 1 \
       -name 'siginfo-failure.acore.tmp.*' | grep -q .; then
    echo "failed crash siginfo capture succeeded, replaced output, or changed crash semantics" >&2
    exit 1
fi
grep -q "getsiginfo for crashing thread.*failed" \
    "$TEST_TMP/siginfo-failure.log"
fi

# Generate one valid acore, then inject an error that appears only from the
# output core's fclose. The converter must fail and retain the prior output.
if [[ $CASE == close || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory 8
expect_status 0 timeout 20s "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/valid.acore"
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
printf 'existing-core-output\n' >"$TEST_TMP/close-fail.core"
cp "$TEST_TMP/close-fail.core" "$TEST_TMP/close-fail.expected"
set +e
ARTHUR_FAIL_FCLOSE=close-fail.core LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -c "$TEST_TMP/valid.acore" \
    -o "$TEST_TMP/close-fail.core" >"$TEST_TMP/close-fail.log" 2>&1
CLOSE_RC=$?
set -e
if [[ $CLOSE_RC -eq 0 || $CLOSE_RC -eq 134 ]] ||
   ! cmp -s "$TEST_TMP/close-fail.expected" "$TEST_TMP/close-fail.core"; then
    echo "close failure was accepted, aborted, or replaced the prior core (rc=$CLOSE_RC)" >&2
    exit 1
fi
grep -q "close output core failed" "$TEST_TMP/close-fail.log"

printf 'existing-core-output\n' >"$TEST_TMP/seek-fail.core"
cp "$TEST_TMP/seek-fail.core" "$TEST_TMP/seek-fail.expected"
set +e
ARTHUR_FAIL_FSEEKO=seek-fail.core LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -c "$TEST_TMP/valid.acore" \
    -o "$TEST_TMP/seek-fail.core" >"$TEST_TMP/seek-fail.log" 2>&1
SEEK_RC=$?
set -e
if [[ $SEEK_RC -eq 0 || $SEEK_RC -eq 134 ]] ||
   ! cmp -s "$TEST_TMP/seek-fail.expected" "$TEST_TMP/seek-fail.core"; then
    echo "seek failure was accepted, aborted, or replaced prior output (rc=$SEEK_RC)" >&2
    exit 1
fi
grep -q "seek to ELF header failed" "$TEST_TMP/seek-fail.log"
fi

# Opening a capture output must not truncate a prior artifact before Arthur
# knows that the requested PID can be attached.
if [[ $CASE == atomic || $CASE == all ]]; then
CASE_RAN=1
# A successful rename is not a durable commit until the containing directory
# has also been synced. The artifact may exist after this injected failure,
# but the command must report that durability was not established.
printf 'directory sync validation\n' >"$TEST_TMP/dir-sync.input"
set +e
ARTHUR_FAIL_DIR_FSYNC=1 LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -1 -o "$TEST_TMP/dir-sync.z4" \
    "$TEST_TMP/dir-sync.input" >"$TEST_TMP/dir-sync.log" 2>&1
DIR_SYNC_RC=$?
set -e
if [[ $DIR_SYNC_RC -eq 0 || ! -f "$TEST_TMP/dir-sync.z4" ]]; then
    echo "directory fsync failure was accepted or lost the already-renamed output" >&2
    exit 1
fi
grep -q "sync output directory .* failed" "$TEST_TMP/dir-sync.log"
if find "$TEST_TMP" -maxdepth 1 -name 'dir-sync.z4.tmp.*' | grep -q .; then
    echo "directory fsync failure retained a temporary output" >&2
    exit 1
fi
printf 'existing-acore-output\n' >"$TEST_TMP/atomic.acore"
cp "$TEST_TMP/atomic.acore" "$TEST_TMP/atomic.expected"
set +e
"$ARTHUR_BIN" -p 2147483647 -1 -o "$TEST_TMP/atomic.acore" \
    >"$TEST_TMP/atomic.log" 2>&1
ATOMIC_RC=$?
set -e
if [[ $ATOMIC_RC -eq 0 ]] ||
   ! cmp -s "$TEST_TMP/atomic.expected" "$TEST_TMP/atomic.acore"; then
    echo "failed capture replaced an existing output (rc=$ATOMIC_RC)" >&2
    exit 1
fi
if find "$TEST_TMP" -maxdepth 1 -name 'atomic.acore.tmp.*' | grep -q .; then
    echo "failed capture retained a temporary output" >&2
    exit 1
fi
printf 'symlink-target\n' >"$TEST_TMP/symlink-target"
ln -s "$TEST_TMP/symlink-target" "$TEST_TMP/atomic-link.acore"
set +e
"$ARTHUR_BIN" -p 2147483647 -1 -o "$TEST_TMP/atomic-link.acore" \
    >"$TEST_TMP/atomic-link.log" 2>&1
LINK_RC=$?
set -e
if [[ $LINK_RC -eq 0 || ! -L "$TEST_TMP/atomic-link.acore" ]] ||
   [[ $(<"$TEST_TMP/symlink-target") != symlink-target ]]; then
    echo "atomic output replaced or modified an existing symlink" >&2
    exit 1
fi

mkfifo "$TEST_TMP/atomic-race.input"
sleep 30 >"$TEST_TMP/atomic-race.input" &
FEEDER_PID=$!
TARGET_PIDS+=("$FEEDER_PID")
"$ARTHUR_BIN" -1 -o "$TEST_TMP/atomic-race.z4" \
    "$TEST_TMP/atomic-race.input" >"$TEST_TMP/atomic-race.log" 2>&1 &
RACE_DUMPER_PID=$!
TARGET_PIDS+=("$RACE_DUMPER_PID")
RACE_TEMP=
for _ in $(seq 1 200); do
    RACE_TEMP=$(find "$TEST_TMP" -maxdepth 1 -type f \
        -name 'atomic-race.z4.tmp.*' -print -quit)
    if [[ -n $RACE_TEMP ]]; then
        break
    fi
    sleep 0.01
done
if [[ -z $RACE_TEMP ]]; then
    echo "atomic race compressor did not create its temporary output" >&2
    exit 1
fi
printf 'concurrent-writer-output\n' >"$TEST_TMP/atomic-race.z4"
kill -TERM "$FEEDER_PID"
set +e
wait "$FEEDER_PID" 2>/dev/null
wait "$RACE_DUMPER_PID"
RACE_COMMIT_RC=$?
set -e
if [[ $RACE_COMMIT_RC -eq 0 ]] ||
   [[ $(<"$TEST_TMP/atomic-race.z4") != concurrent-writer-output ]]; then
    echo "atomic commit overwrote an output created during compression" >&2
    exit 1
fi
if find "$TEST_TMP" -maxdepth 1 -name 'atomic-race.z4.tmp.*' | grep -q .; then
    echo "failed no-replace commit retained a temporary output" >&2
    exit 1
fi

printf 'initial-existing-output\n' >"$TEST_TMP/atomic-replace.z4"
mkfifo "$TEST_TMP/atomic-replace.input"
sleep 30 >"$TEST_TMP/atomic-replace.input" &
REPLACE_FEEDER_PID=$!
TARGET_PIDS+=("$REPLACE_FEEDER_PID")
"$ARTHUR_BIN" -1 -o "$TEST_TMP/atomic-replace.z4" \
    "$TEST_TMP/atomic-replace.input" >"$TEST_TMP/atomic-replace.log" 2>&1 &
REPLACE_DUMPER_PID=$!
TARGET_PIDS+=("$REPLACE_DUMPER_PID")
REPLACE_TEMP=
for _ in $(seq 1 200); do
    REPLACE_TEMP=$(find "$TEST_TMP" -maxdepth 1 -type f \
        -name 'atomic-replace.z4.tmp.*' -print -quit)
    if [[ -n $REPLACE_TEMP ]]; then
        break
    fi
    sleep 0.01
done
if [[ -z $REPLACE_TEMP ]]; then
    echo "existing-output race did not create its temporary output" >&2
    exit 1
fi
printf 'replacement-writer-output\n' >"$TEST_TMP/atomic-replacement.new"
mv "$TEST_TMP/atomic-replacement.new" "$TEST_TMP/atomic-replace.z4"
kill -TERM "$REPLACE_FEEDER_PID"
set +e
wait "$REPLACE_FEEDER_PID" 2>/dev/null
wait "$REPLACE_DUMPER_PID"
REPLACE_COMMIT_RC=$?
set -e
if [[ $REPLACE_COMMIT_RC -eq 0 ]] ||
   [[ $(<"$TEST_TMP/atomic-replace.z4") != replacement-writer-output ]]; then
    echo "atomic commit overwrote a replacement of its initial output" >&2
    exit 1
fi
if find "$TEST_TMP" -maxdepth 1 -name 'atomic-replace.z4.tmp.*' | grep -q .; then
    echo "failed identity-checked commit retained a temporary output" >&2
    exit 1
fi

# Replace the initial output after commit's last preflight lstat has returned.
# The commit must detect the inode displaced by RENAME_EXCHANGE, restore it,
# and fail without publishing Arthur's temporary stream.
printf 'last-window-initial-output\n' >"$TEST_TMP/atomic-last-window.z4"
printf 'last-window-input\n' >"$TEST_TMP/atomic-last-window.input"
set +e
ARTHUR_SWAP_OUTPUT_AFTER_LSTAT="$TEST_TMP/atomic-last-window.z4" \
    LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -1 -o "$TEST_TMP/atomic-last-window.z4" \
    "$TEST_TMP/atomic-last-window.input" \
    >"$TEST_TMP/atomic-last-window.log" 2>&1
LAST_WINDOW_RC=$?
set -e
if [[ $LAST_WINDOW_RC -eq 0 ]] ||
   [[ $(<"$TEST_TMP/atomic-last-window.z4") != last-window-writer-output ]]; then
    echo "atomic commit overwrote a writer in the final lstat/rename window" >&2
    exit 1
fi
grep -q "changed identity or type during commit" \
    "$TEST_TMP/atomic-last-window.log"
if find "$TEST_TMP" -maxdepth 1 -name 'atomic-last-window.z4.tmp.*' | grep -q .; then
    echo "failed exchange-checked commit retained a temporary output" >&2
    exit 1
fi

# A legal final basename can consume NAME_MAX by itself. The temporary suffix
# must fall back to a short same-directory name without weakening atomic commit.
printf 'long basename roundtrip\n' >"$TEST_TMP/long-basename.input"
printf -v LONG_COMPRESSED '%0250d' 0
printf -v LONG_DECOMPRESSED '%0250d' 1
expect_status 0 "$ARTHUR_BIN" -1 \
    -o "$TEST_TMP/$LONG_COMPRESSED" "$TEST_TMP/long-basename.input"
expect_status 0 "$ARTHUR_BIN" -2 \
    "$TEST_TMP/$LONG_COMPRESSED" "$TEST_TMP/$LONG_DECOMPRESSED"
cmp "$TEST_TMP/long-basename.input" "$TEST_TMP/$LONG_DECOMPRESSED"
if find "$TEST_TMP" -maxdepth 1 -name '.arthur.tmp.*' | grep -q .; then
    echo "long basename roundtrip retained a temporary output" >&2
    exit 1
fi
fi

# New test streams carry per-block CRC32. Flipping one literal byte must be
# detected even when LZ4 can still decode the structurally valid block.
if [[ $CASE == checksum || $CASE == all ]]; then
CASE_RAN=1
dd if=/dev/urandom of="$TEST_TMP/checksum.input" bs=4096 count=32 status=none
expect_status 0 "$ARTHUR_BIN" -1 -o "$TEST_TMP/checksum.z4" \
    "$TEST_TMP/checksum.input"
expect_status 0 "$ARTHUR_BIN" -2 "$TEST_TMP/checksum.z4" \
    "$TEST_TMP/checksum.roundtrip"
cmp "$TEST_TMP/checksum.input" "$TEST_TMP/checksum.roundtrip"
cp "$TEST_TMP/checksum.z4" "$TEST_TMP/checksum-corrupt.z4"
flip_byte "$TEST_TMP/checksum-corrupt.z4" 1024
printf 'existing-decompressed-output\n' >"$TEST_TMP/checksum.output"
cp "$TEST_TMP/checksum.output" "$TEST_TMP/checksum.expected"
set +e
"$ARTHUR_BIN" -2 "$TEST_TMP/checksum-corrupt.z4" \
    "$TEST_TMP/checksum.output" >"$TEST_TMP/checksum.log" 2>&1
CHECKSUM_RC=$?
set -e
if [[ $CHECKSUM_RC -eq 0 ]] ||
   ! cmp -s "$TEST_TMP/checksum.expected" "$TEST_TMP/checksum.output"; then
    echo "corrupt compressed stream was accepted or replaced prior output" >&2
    exit 1
fi
grep -q "block checksum mismatch" "$TEST_TMP/checksum.log"

start_fixture memory 8
expect_status 0 "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/checksum.acore"
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
cp "$TEST_TMP/checksum.acore" "$TEST_TMP/checksum-corrupt.acore"
read -r header0 header1 header2 < <(od -An -tu1 -j 8 -N 3 \
    "$TEST_TMP/checksum-corrupt.acore")
packed_header=$((header0 | (header1 << 8) | (header2 << 16)))
first_block_size=$((packed_header >> 5))
first_checksum_offset=$((8 + 3 + first_block_size))
flip_byte "$TEST_TMP/checksum-corrupt.acore" "$first_checksum_offset"
printf 'existing-core-output\n' >"$TEST_TMP/checksum.core"
cp "$TEST_TMP/checksum.core" "$TEST_TMP/checksum-core.expected"
set +e
"$ARTHUR_BIN" -c "$TEST_TMP/checksum-corrupt.acore" \
    -o "$TEST_TMP/checksum.core" >"$TEST_TMP/checksum-acore.log" 2>&1
ACORE_CHECKSUM_RC=$?
set -e
if [[ $ACORE_CHECKSUM_RC -eq 0 ]] ||
   ! cmp -s "$TEST_TMP/checksum-core.expected" "$TEST_TMP/checksum.core"; then
    echo "corrupt acore was accepted or replaced prior output" >&2
    exit 1
fi
grep -q "block checksum mismatch" "$TEST_TMP/checksum-acore.log"
fi

# Version zero was never a valid acore format. Reject it at the header boundary
# rather than parsing it with legacy v1-v3 rules.
if [[ $CASE == format || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory 8
expect_status 0 "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/format.acore"
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
cp "$TEST_TMP/format.acore" "$TEST_TMP/version-zero.acore"
printf '\0\0' | dd of="$TEST_TMP/version-zero.acore" bs=1 seek=6 \
    conv=notrunc status=none
printf 'existing-format-output\n' >"$TEST_TMP/format.core"
cp "$TEST_TMP/format.core" "$TEST_TMP/format.expected"
set +e
"$ARTHUR_BIN" -c "$TEST_TMP/version-zero.acore" \
    -o "$TEST_TMP/format.core" >"$TEST_TMP/format.log" 2>&1
FORMAT_RC=$?
set -e
if [[ $FORMAT_RC -eq 0 ]] ||
   ! cmp -s "$TEST_TMP/format.expected" "$TEST_TMP/format.core"; then
    echo "invalid acore version was accepted or replaced prior output" >&2
    exit 1
fi
grep -q "unsupported acore version 0" "$TEST_TMP/format.log"

"$TEST_TMP/acore_format_test" "$TEST_TMP/process-trailing.acore" \
    "$TEST_TMP/thread-trailing.acore" "$TEST_TMP/process-continuation.acore"
for malformed in process-trailing thread-trailing process-continuation; do
    printf 'existing-format-output\n' >"$TEST_TMP/$malformed.core"
    cp "$TEST_TMP/$malformed.core" "$TEST_TMP/$malformed.expected"
    set +e
    "$ARTHUR_BIN" -c "$TEST_TMP/$malformed.acore" \
        -o "$TEST_TMP/$malformed.core" >"$TEST_TMP/$malformed.log" 2>&1
    MALFORMED_RC=$?
    set -e
    if [[ $MALFORMED_RC -eq 0 ]] ||
       ! cmp -s "$TEST_TMP/$malformed.expected" "$TEST_TMP/$malformed.core"; then
        echo "malformed $malformed acore was accepted or replaced prior output" >&2
        exit 1
    fi
done
grep -q "PROCESS block has an unexpected payload length" \
    "$TEST_TMP/process-trailing.log"
grep -q "thread block 0 has 1 trailing bytes" "$TEST_TMP/thread-trailing.log"
grep -q "PROCESS metadata starts with a continuation block" \
    "$TEST_TMP/process-continuation.log"

"$TEST_TMP/acore_format_test" --load-budget "$TEST_TMP/load-budget.acore"
"$TEST_TMP/acore_format_test" --wrong-phdr "$TEST_TMP/wrong-phdr.acore"
"$TEST_TMP/acore_format_test" --unaligned-file-offset \
    "$TEST_TMP/unaligned-file-offset.acore"
for malformed in load-budget wrong-phdr unaligned-file-offset; do
    printf 'existing-format-output\n' >"$TEST_TMP/$malformed.core"
    cp "$TEST_TMP/$malformed.core" "$TEST_TMP/$malformed.expected"
    set +e
    "$ARTHUR_BIN" -c "$TEST_TMP/$malformed.acore" \
        -o "$TEST_TMP/$malformed.core" >"$TEST_TMP/$malformed.log" 2>&1
    MALFORMED_RC=$?
    set -e
    if [[ $MALFORMED_RC -eq 0 ]] ||
       ! cmp -s "$TEST_TMP/$malformed.expected" "$TEST_TMP/$malformed.core"; then
        echo "malformed $malformed acore was accepted or replaced prior output" >&2
        exit 1
    fi
done
grep -q "LOADS stream exceeds maps-derived budget" "$TEST_TMP/load-budget.log"
grep -q "ELF LOAD 0 differs from maps-derived layout" "$TEST_TMP/wrong-phdr.log"
grep -q "mapped file offset 1 is not aligned" \
    "$TEST_TMP/unaligned-file-offset.log"

"$TEST_TMP/acore_format_test" --credentials-v5 \
    "$TEST_TMP/credentials-v5.acore"
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/credentials-v5.acore" \
    -o "$TEST_TMP/credentials-v5.core"
"$TEST_TMP/core_note_test" "$TEST_TMP/credentials-v5.core" \
    123 234 0 0x600 1

"$TEST_TMP/acore_format_test" --legacy-v4 "$TEST_TMP/legacy-v4.acore"
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/legacy-v4.acore" \
    -o "$TEST_TMP/legacy-v4.core"
"$TEST_TMP/core_note_test" "$TEST_TMP/legacy-v4.core" \
    1001 1002 0 0x600 1

"$TEST_TMP/acore_format_test" --zero-signal-masks \
    "$TEST_TMP/zero-signal-masks.acore"
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/zero-signal-masks.acore" \
    -o "$TEST_TMP/zero-signal-masks.core"
"$TEST_TMP/core_note_test" "$TEST_TMP/zero-signal-masks.core" \
    0 0 0 0x600 1 0 0 1 "$XSTATE_NOTE_COUNT"

"$TEST_TMP/acore_format_test" --invalid-fp "$TEST_TMP/invalid-fp.acore"
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/invalid-fp.acore" \
    -o "$TEST_TMP/invalid-fp.core"
"$TEST_TMP/core_note_test" "$TEST_TMP/invalid-fp.core" \
    0 0 0 0x600 1 0 0 0 0

"$TEST_TMP/acore_format_test" --crash-signal-mismatch \
    "$TEST_TMP/crash-signal-mismatch.acore"
printf 'existing-format-output\n' >"$TEST_TMP/crash-signal-mismatch.core"
cp "$TEST_TMP/crash-signal-mismatch.core" \
    "$TEST_TMP/crash-signal-mismatch.expected"
set +e
"$ARTHUR_BIN" -c "$TEST_TMP/crash-signal-mismatch.acore" \
    -o "$TEST_TMP/crash-signal-mismatch.core" \
    >"$TEST_TMP/crash-signal-mismatch.log" 2>&1
MISMATCH_RC=$?
set -e
if [[ $MISMATCH_RC -eq 0 ]] ||
   ! cmp -s "$TEST_TMP/crash-signal-mismatch.expected" \
       "$TEST_TMP/crash-signal-mismatch.core"; then
    echo "inconsistent v5 crash signal was accepted or replaced prior output" >&2
    exit 1
fi
grep -q "disagrees with crash signal" "$TEST_TMP/crash-signal-mismatch.log"
fi

# Decompression cleanup must leave a Coredump object reusable. This also
# exercises the note-size overflow path without attempting a giant allocation.
if [[ $CASE == reuse || $CASE == all ]]; then
CASE_RAN=1
${CXX:-g++} -std=c++11 -Wall -Wextra -Wno-missing-field-initializers \
    -I"$ARTHUR_DIR/src" -I"$ARTHUR_DIR/include" \
    "$ARTHUR_DIR/tests/reuse_test.cc" \
    "$ARTHUR_DIR/build/core.o" "$ARTHUR_DIR/build/proc.o" \
    "$ARTHUR_DIR/build/lz4.o" -L"$ARTHUR_DIR/lib" "$LZ4_TEST_LIBRARY" \
    -ldl -no-pie -o "$TEST_TMP/reuse_test"
start_fixture memory 8
expect_status 0 "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/reuse.acore"
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
expect_status 0 "$TEST_TMP/reuse_test" "$TEST_TMP/reuse.acore" \
    "$TEST_TMP/reuse-1.core" "$TEST_TMP/reuse-2.core"
cmp "$TEST_TMP/reuse-1.core" "$TEST_TMP/reuse-2.core"
fi

# TailMark terminates the whole file, not merely the first embedded stream.
# Appended bytes must fail closed in both converter paths and preserve an
# existing destination until the complete input has been validated.
if [[ $CASE == trailing || $CASE == all ]]; then
CASE_RAN=1
dd if=/dev/urandom of="$TEST_TMP/trailing.input" bs=4096 count=8 status=none
expect_status 0 "$ARTHUR_BIN" -1 -o "$TEST_TMP/trailing.z4" \
    "$TEST_TMP/trailing.input"
printf 'EXTRA' >>"$TEST_TMP/trailing.z4"
printf 'existing-decompressed-output\n' >"$TEST_TMP/trailing.output"
cp "$TEST_TMP/trailing.output" "$TEST_TMP/trailing.expected"
set +e
"$ARTHUR_BIN" -2 "$TEST_TMP/trailing.z4" \
    "$TEST_TMP/trailing.output" >"$TEST_TMP/trailing.log" 2>&1
TRAILING_RC=$?
set -e
if [[ $TRAILING_RC -eq 0 ]] ||
   ! cmp -s "$TEST_TMP/trailing.expected" "$TEST_TMP/trailing.output"; then
    echo "test stream trailing data was accepted or replaced prior output" >&2
    exit 1
fi
grep -q "trailing data after tail mark" "$TEST_TMP/trailing.log"
if grep -Eq 'write [0-9]+ bytes\.' "$TEST_TMP/trailing.log"; then
    echo "failed decompression reported a successful byte count" >&2
    exit 1
fi

start_fixture memory 8
expect_status 0 "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/trailing.acore"
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
printf 'EXTRA' >>"$TEST_TMP/trailing.acore"
printf 'existing-core-output\n' >"$TEST_TMP/trailing.core"
cp "$TEST_TMP/trailing.core" "$TEST_TMP/trailing-core.expected"
set +e
"$ARTHUR_BIN" -c "$TEST_TMP/trailing.acore" \
    -o "$TEST_TMP/trailing.core" >"$TEST_TMP/trailing-acore.log" 2>&1
ACORE_TRAILING_RC=$?
set -e
if [[ $ACORE_TRAILING_RC -eq 0 ]] ||
   ! cmp -s "$TEST_TMP/trailing-core.expected" "$TEST_TMP/trailing.core"; then
    echo "acore trailing data was accepted or replaced prior output" >&2
    exit 1
fi
grep -q "trailing data after tail mark" "$TEST_TMP/trailing-acore.log"
fi

# A directory read error after a valid TID is still an incomplete enumeration.
# Capture must fail instead of publishing a leader-only archive.
if [[ $CASE == task-enumeration || $CASE == all ]]; then
CASE_RAN=1
start_fixture late-thread
set +e
ARTHUR_TARGET_PID="$FIXTURE_PID" ARTHUR_FAIL_TASK_READDIR=1 \
    LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
    -o "$TEST_TMP/task-enumeration.acore" \
    >"$TEST_TMP/task-enumeration.log" 2>&1
TASK_ENUM_RC=$?
set -e
if [[ $TASK_ENUM_RC -eq 0 || -e "$TEST_TMP/task-enumeration.acore" ]] ||
   ! kill -0 "$FIXTURE_PID" 2>/dev/null ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]]; then
    echo "partial task enumeration published an archive or left target traced" >&2
    exit 1
fi
grep -q "failed to collect threads\|cannot enumerate threads" \
    "$TEST_TMP/task-enumeration.log"
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
fi

# An I/O error while classifying a TRACECLONE child is not evidence that the
# child is a separate process. Stop monitoring and detach the complete set.
if [[ $CASE == clone-identity || $CASE == all ]]; then
CASE_RAN=1
start_fixture spawn-worker
(
    cd "$TEST_TMP"
    exec timeout 20s env ARTHUR_TARGET_PID="$FIXTURE_PID" \
        ARTHUR_FAIL_THREAD_ACCESS=1 LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
        "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
        -o "$TEST_TMP/clone-identity.acore"
) >"$TEST_TMP/clone-identity.log" 2>&1 &
CLONE_ID_WRAPPER=$!
TARGET_PIDS+=("$CLONE_ID_WRAPPER")
wait_for_log "$TEST_TMP/clone-identity.log" "Launched in monitor mode"
kill -USR2 "$FIXTURE_PID"
wait_for_log "$TEST_TMP/fixture.log" "spawn-worker-tid="
set +e
wait "$CLONE_ID_WRAPPER"
CLONE_ID_RC=$?
set -e
if [[ $CLONE_ID_RC -eq 0 || $CLONE_ID_RC -eq 124 ]] ||
   ! kill -0 "$FIXTURE_PID" 2>/dev/null ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]] ||
   [[ -e "$TEST_TMP/clone-identity.acore" ]]; then
    echo "clone identity I/O failure was ignored or left monitor ownership" >&2
    exit 1
fi
grep -q "cannot determine thread-group identity" "$TEST_TMP/clone-identity.log"
kill -TERM "$FIXTURE_PID"
expect_status 143 wait "$FIXTURE_PID"
fi

# Failure to read SigCgt/SigIgn must not turn an ignored SIGQUIT into a false
# fatal crash. Relay the pending signal and end monitoring without publication.
if [[ $CASE == disposition-read || $CASE == all ]]; then
CASE_RAN=1
start_fixture ignore-quit
(
    cd "$TEST_TMP"
    exec timeout 20s env ARTHUR_TARGET_PID="$FIXTURE_PID" \
        ARTHUR_FAIL_STATUS_READ=1 LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
        "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
        -o "$TEST_TMP/disposition-read.acore"
) >"$TEST_TMP/disposition-read.log" 2>&1 &
DISPOSITION_WRAPPER=$!
TARGET_PIDS+=("$DISPOSITION_WRAPPER")
wait_for_log "$TEST_TMP/disposition-read.log" "Launched in monitor mode"
kill -QUIT "$FIXTURE_PID"
set +e
wait "$DISPOSITION_WRAPPER"
DISPOSITION_RC=$?
set -e
if [[ $DISPOSITION_RC -eq 0 || $DISPOSITION_RC -eq 124 ]] ||
   ! kill -0 "$FIXTURE_PID" 2>/dev/null ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]] ||
   [[ -e "$TEST_TMP/disposition-read.acore" ]]; then
    echo "unknown signal disposition produced a false crash or retained tracing" >&2
    exit 1
fi
grep -q "cannot determine disposition" "$TEST_TMP/disposition-read.log"
kill -TERM "$FIXTURE_PID"
expect_status 143 wait "$FIXTURE_PID"
fi

# A mode-0 COW child containing Arthur's injected zero at [rsp-8] is not a
# usable snapshot. Restoration failure must discard it and restore the target.
if [[ $CASE == child-stack-restore || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory-spin 8
set +e
ARTHUR_FAIL_CHILD_POKEDATA=1 LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
    "$ARTHUR_BIN" -p "$FIXTURE_PID" -0 \
    -o "$TEST_TMP/child-stack-restore.acore" \
    >"$TEST_TMP/child-stack-restore.log" 2>&1
CHILD_STACK_RC=$?
set -e
if [[ $CHILD_STACK_RC -eq 0 || -e "$TEST_TMP/child-stack-restore.acore" ]] ||
   ! kill -0 "$FIXTURE_PID" 2>/dev/null ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]]; then
    echo "polluted COW child was published, retained, or target was not restored" >&2
    exit 1
fi
for CHILD_PID in $(pgrep -P "$FIXTURE_PID" || true); do
    if [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$CHILD_PID/status" 2>/dev/null || echo 0) != 0 ]]; then
        echo "polluted COW child remained owned by Arthur" >&2
        exit 1
    fi
done
grep -q "discarding polluted snapshot" "$TEST_TMP/child-stack-restore.log"
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
fi

# pt_call operation failure and pt_call restoration failure are distinct. A
# monitor that cannot restore XSTATE must exit rather than serve later dumps.
if [[ $CASE == pt-call-recovery || $CASE == all ]]; then
CASE_RAN=1
if [[ $(uname -m) != aarch64 ]]; then
    start_fixture memory-spin 8
    (
        cd "$TEST_TMP"
        exec timeout 20s env ARTHUR_TARGET_PID="$FIXTURE_PID" \
            ARTHUR_FAIL_SETXSTATE=1 LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
            "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
            -o "$TEST_TMP/pt-call-recovery.acore"
    ) >"$TEST_TMP/pt-call-recovery.log" 2>&1 &
    PT_CALL_WRAPPER=$!
    TARGET_PIDS+=("$PT_CALL_WRAPPER")
    wait_for_log "$TEST_TMP/pt-call-recovery.log" "Launched in monitor mode"
    PT_CALL_MONITOR=$(find_timeout_child "$PT_CALL_WRAPPER")
    kill -USR1 "$PT_CALL_MONITOR"
    set +e
    wait "$PT_CALL_WRAPPER"
    PT_CALL_RC=$?
    set -e
    if [[ $PT_CALL_RC -eq 0 || $PT_CALL_RC -eq 124 ]] ||
       ! kill -0 "$FIXTURE_PID" 2>/dev/null ||
       [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]] ||
       find "$TEST_TMP" -maxdepth 1 -type f \
           -name "acore.$FIXTURE_PID.*" | grep -q .; then
        echo "pt_call restoration failure was ignored or published a snapshot" >&2
        exit 1
    fi
    grep -q "restore xstate" "$TEST_TMP/pt-call-recovery.log"
    kill -KILL "$FIXTURE_PID"
    set +e
    wait "$FIXTURE_PID" 2>/dev/null
    set -e
fi
fi

# A tracee stopped in a leaf frame has rsp == 8 (mod 16). Every remote libc or
# injected-shellcode entry must preserve the SysV callee-entry alignment.
if [[ $CASE == call-alignment || $CASE == all ]]; then
CASE_RAN=1
if [[ $(uname -m) != aarch64 ]]; then
    start_fixture leaf-stack-spin
    expect_status 0 env ARTHUR_REQUIRE_CALL_STACK_ALIGNMENT=1 \
        LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
        "$ARTHUR_BIN" -p "$FIXTURE_PID" -0 \
        -o "$TEST_TMP/call-alignment.acore"
    if ! kill -0 "$FIXTURE_PID" 2>/dev/null ||
       [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]]; then
        echo "aligned remote calls failed to restore the leaf-frame target" >&2
        exit 1
    fi
    expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/call-alignment.acore" \
        -o "$TEST_TMP/call-alignment.core"
    kill -KILL "$FIXTURE_PID"
    set +e
    wait "$FIXTURE_PID" 2>/dev/null
    set -e
fi
fi

# ESRCH from DETACH does not prove a snapshot child disappeared. If /proc still
# shows Arthur as tracer, use the explicit kill/wait fallback and then publish.
if [[ $CASE == child-detach-esrch || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory-spin 8
(
    cd "$TEST_TMP"
    exec timeout 20s env ARTHUR_FAIL_CHILD_DETACH_ESRCH=1 \
        LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
        "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
        -o "$TEST_TMP/child-detach-esrch-seed.acore"
) >"$TEST_TMP/child-detach-esrch.log" 2>&1 &
CHILD_ESRCH_WRAPPER=$!
TARGET_PIDS+=("$CHILD_ESRCH_WRAPPER")
wait_for_log "$TEST_TMP/child-detach-esrch.log" "Launched in monitor mode"
CHILD_ESRCH_MONITOR=$(find_timeout_child "$CHILD_ESRCH_WRAPPER")
kill -USR1 "$CHILD_ESRCH_MONITOR"
wait_for_log "$TEST_TMP/child-detach-esrch.log" "writing out acore finished"
grep -q "using kill fallback" "$TEST_TMP/child-detach-esrch.log"
CHILD_ESRCH_SNAPSHOT=$(find "$TEST_TMP" -maxdepth 1 -type f \
    -name "acore.$FIXTURE_PID.*" -print -quit)
if [[ -z $CHILD_ESRCH_SNAPSHOT ]] || pgrep -P "$FIXTURE_PID" >/dev/null; then
    echo "DETACH ESRCH fallback did not publish cleanly or retained child" >&2
    exit 1
fi
expect_status 0 "$ARTHUR_BIN" -c "$CHILD_ESRCH_SNAPSHOT" \
    -o "$TEST_TMP/child-detach-esrch.core"
kill -TERM "$FIXTURE_PID"
expect_status 143 wait "$FIXTURE_PID"
expect_status 0 wait "$CHILD_ESRCH_WRAPPER"
fi

# A real crash delivered during fork or munmap injection must become the final
# monitored crash archive; cleanup must not resume the target with signal zero.
if [[ $CASE == injection-crash || $CASE == all ]]; then
CASE_RAN=1
for CRASH_CONT in 3 4; do
    start_fixture memory-spin 8
    mkdir -p "$TEST_TMP/injection-crash-$CRASH_CONT"
    (
        cd "$TEST_TMP/injection-crash-$CRASH_CONT"
        exec timeout 20s env ARTHUR_TARGET_PID="$FIXTURE_PID" \
            ARTHUR_CRASH_ON_CONT="$CRASH_CONT" \
            LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
            "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
            -o "$TEST_TMP/injection-crash-$CRASH_CONT.acore"
    ) >"$TEST_TMP/injection-crash-$CRASH_CONT.log" 2>&1 &
    INJECTION_WRAPPER=$!
    TARGET_PIDS+=("$INJECTION_WRAPPER")
    wait_for_log "$TEST_TMP/injection-crash-$CRASH_CONT.log" \
        "Launched in monitor mode"
    INJECTION_MONITOR=$(find_timeout_child "$INJECTION_WRAPPER")
    kill -USR1 "$INJECTION_MONITOR"
    expect_status 139 wait "$FIXTURE_PID"
    expect_status 0 wait "$INJECTION_WRAPPER"
    if [[ ! -s "$TEST_TMP/injection-crash-$CRASH_CONT.acore" ]]; then
        echo "crash at injection CONT $CRASH_CONT did not produce final acore" >&2
        exit 1
    fi
    expect_status 0 "$ARTHUR_BIN" \
        -c "$TEST_TMP/injection-crash-$CRASH_CONT.acore" \
        -o "$TEST_TMP/injection-crash-$CRASH_CONT.core"
done
fi

# Crash capture is not successful if Arthur cannot detach every crash tracee,
# even when fallback signal delivery can terminate the process.
if [[ $CASE == crash-detach || $CASE == all ]]; then
CASE_RAN=1
for DETACH_FAILURE in always esrch-always; do
    start_fixture worker-crash
    timeout 20s env ARTHUR_FAIL_DETACH="$DETACH_FAILURE" \
        LD_PRELOAD="$TEST_TMP/fclose_fail.so" \
        "$ARTHUR_BIN" -p "$FIXTURE_PID" -3 \
        -o "$TEST_TMP/crash-detach-$DETACH_FAILURE.acore" \
        >"$TEST_TMP/crash-detach-$DETACH_FAILURE.log" 2>&1 &
    CRASH_DETACH_MONITOR=$!
    TARGET_PIDS+=("$CRASH_DETACH_MONITOR")
    wait_for_log "$TEST_TMP/crash-detach-$DETACH_FAILURE.log" \
        "Launched in monitor mode"
    kill -USR2 "$FIXTURE_PID"
    set +e
    wait "$FIXTURE_PID"
    CRASH_DETACH_TARGET_RC=$?
    wait "$CRASH_DETACH_MONITOR"
    CRASH_DETACH_RC=$?
    set -e
    if [[ $CRASH_DETACH_TARGET_RC -ne 139 || $CRASH_DETACH_RC -eq 0 ]] ||
       [[ -e "$TEST_TMP/crash-detach-$DETACH_FAILURE.acore" ]]; then
        echo "crash DETACH $DETACH_FAILURE reported success or published an acore" >&2
        exit 1
    fi
    grep -q "could not release every crashed tracee" \
        "$TEST_TMP/crash-detach-$DETACH_FAILURE.log"
done
fi

# pid and output are singleton options. Repetition must be rejected before any
# target access or output creation, including mixed long/short spellings.
if [[ $CASE == duplicate-options || $CASE == all ]]; then
CASE_RAN=1
expect_status 2 "$ARTHUR_BIN" --pid 999999 -p 888888 \
    -o "$TEST_TMP/duplicate-pid.acore"
expect_status 2 "$ARTHUR_BIN" -1 "$TEST_TMP/no-such-input" \
    --output "$TEST_TMP/duplicate-output-a" \
    -o "$TEST_TMP/duplicate-output-b"
if [[ -e "$TEST_TMP/duplicate-pid.acore" ||
      -e "$TEST_TMP/duplicate-output-a" ||
      -e "$TEST_TMP/duplicate-output-b" ]]; then
    echo "duplicate singleton options performed I/O" >&2
    exit 1
fi
fi

# Arthur must run under a valid 1.5 MiB stack limit. Large capture buffers live
# on the heap; startup no longer prefaults a useless 2 MiB automatic array.
if [[ $CASE == low-stack || $CASE == all ]]; then
CASE_RAN=1
start_fixture memory 8
set +e
(
    ulimit -s 1536
    exec "$ARTHUR_BIN" -p "$FIXTURE_PID" -1 \
        -o "$TEST_TMP/low-stack.acore"
) >"$TEST_TMP/low-stack.log" 2>&1
LOW_STACK_RC=$?
set -e
if [[ $LOW_STACK_RC -ne 0 || ! -s "$TEST_TMP/low-stack.acore" ]] ||
   ! kill -0 "$FIXTURE_PID" 2>/dev/null ||
   [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$FIXTURE_PID/status") != 0 ]]; then
    echo "capture failed under a valid 1.5 MiB stack limit" >&2
    exit 1
fi
expect_status 0 "$ARTHUR_BIN" -c "$TEST_TMP/low-stack.acore" \
    -o "$TEST_TMP/low-stack.core"
kill -KILL "$FIXTURE_PID"
set +e
wait "$FIXTURE_PID" 2>/dev/null
set -e
fi

if [[ $CASE_RAN -eq 0 ]]; then
    echo "unknown or unexecuted Arthur regression case '$CASE'" >&2
    exit 2
fi

echo "Arthur regression case '$CASE' passed"
