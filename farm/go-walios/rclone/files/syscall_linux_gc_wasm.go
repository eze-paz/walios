// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && gc && wasm

// linux/wasm (Go on walios): no SYSCALL instruction, so the entry points other ports
// implement in asm_linux_*.s are Go functions over package syscall, whose
// RawSyscall6 is the WALI import dispatcher.

package unix

import (
	"syscall"
	"unsafe"
)

func Syscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.Syscall(trap, a1, a2, a3)
}

func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.Syscall6(trap, a1, a2, a3, a4, a5, a6)
}

func RawSyscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.RawSyscall(trap, a1, a2, a3)
}

func RawSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.RawSyscall6(trap, a1, a2, a3, a4, a5, a6)
}

func SyscallNoError(trap, a1, a2, a3 uintptr) (r1, r2 uintptr) {
	r1, r2, _ = syscall.Syscall(trap, a1, a2, a3)
	return
}

func RawSyscallNoError(trap, a1, a2, a3 uintptr) (r1, r2 uintptr) {
	r1, r2, _ = syscall.RawSyscall(trap, a1, a2, a3)
	return
}

func gettimeofday(tv *Timeval) (err syscall.Errno) {
	_, _, err = syscall.RawSyscall(SYS_GETTIMEOFDAY, uintptr(unsafe.Pointer(tv)), 0, 0)
	return
}
