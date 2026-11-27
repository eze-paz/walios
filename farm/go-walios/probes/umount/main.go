package main

import (
	"fmt"
	"os"
	"syscall"
)

// umount DIR (busybox in walios has no umount applet).
func main() {
	err := syscall.Unmount(os.Args[1], 0)
	fmt.Println("umount", os.Args[1], err)
}
