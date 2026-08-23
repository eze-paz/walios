# Real fork() for the Asyncify substrate

The vfork-as-macro (fork()==vfork()==__wali_fork_begin+setjmp) is gated in
`include/unistd.h` so that building with `-D__WALI_ASYNCIFY_FORK` gives the REAL
musl fork() (which calls _Fork -> SYS_fork). The host answers SYS_fork by unwinding
the caller (Asyncify), copying linear memory into a child instance, and rewinding
both to the fork point (parent<-pid, child<-0). Binaries built this way are then
processed with:

    wasm-opt --asyncify --pass-arg=asyncify-imports@wali.SYS_fork  in.wasm -o out.wasm

Only SYS_fork is an asyncify import, so blocking syscalls keep using JSPI and are
not replayed during rewind.

Header change (include/unistd.h):

    #if !defined(__WALI_LIBC_INTERNAL) && !defined(__WALI_ASYNCIFY_FORK)
    ... vfork()/fork() macros ...
    #endif
