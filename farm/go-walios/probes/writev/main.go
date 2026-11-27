package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// writev with two buffers: the iovec array carries pointers (8 bytes in Go's linux/amd64
// layout, 4 in walios' C ABI). Prints what landed in the file.
func main() {
	f, _ := os.Create("/tmp/wv.txt")
	a, b := []byte("hello "), []byte("world\n")
	iov := []syscall.Iovec{{Base: &a[0], Len: uint64(len(a))}, {Base: &b[0], Len: uint64(len(b))}}
	n, _, e := syscall.Syscall(syscall.SYS_WRITEV, f.Fd(), uintptr(unsafe.Pointer(&iov[0])), 2)
	f.Close()
	got, _ := os.ReadFile("/tmp/wv.txt")
	fmt.Printf("writev n=%d errno=%v file=%q\n", n, e, got)
}
