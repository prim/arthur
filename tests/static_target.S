#if defined(__x86_64__)
.global _start
.section .text
_start:
    mov $157, %rax
    mov $0x59616d61, %rdi
    mov $-1, %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    xor %r8, %r8
    syscall

    mov $1, %rax
    mov $1, %rdi
    lea ready(%rip), %rsi
    mov $6, %rdx
    syscall
1:
    mov $34, %rax
    syscall
    jmp 1b
#elif defined(__aarch64__)
.global _start
.section .text
_start:
    mov x8, #167
    movz x0, #0x6d61
    movk x0, #0x5961, lsl #16
    mov x1, #-1
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    svc #0

    mov x8, #64
    mov x0, #1
    adr x1, ready
    mov x2, #6
    svc #0
1:
    b 1b
#else
#error unsupported architecture
#endif

.section .rodata
ready:
    .ascii "ready\n"

.section .note.GNU-stack,"",@progbits
