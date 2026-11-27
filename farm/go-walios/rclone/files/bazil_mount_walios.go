//go:build linux && wasm

// bazil.org/fuse on walios (Go linux/wasm): there is no fusermount3 helper and Go cannot
// start processes there yet, so mount like a root process does: open /dev/fuse ourselves
// and mount(2) it with fd=N. The fd is non-blocking and wrapped in an *os.File so reads
// go through Go's netpoller: the runtime is single-threaded, and a blocking read of
// /dev/fuse would freeze the goroutines that answer earlier requests.

package fuse

import (
	"fmt"
	"os"
	"syscall"
)

func mount(dir string, conf *mountConfig) (*os.File, error) {
	fd, err := syscall.Open("/dev/fuse", syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/fuse: %v", err)
	}
	opts := fmt.Sprintf("fd=%d,rootmode=40000,user_id=%d,group_id=%d", fd, os.Getuid(), os.Getgid())
	if o := conf.getOptions(); o != "" {
		opts += "," + o
	}
	fstype := "fuse"
	if st, ok := conf.options["subtype"]; ok && st != "" {
		fstype = "fuse." + st
	}
	src := conf.options["fsname"]
	if src == "" {
		src = "fuse"
	}
	if err := syscall.Mount(src, dir, fstype, syscall.MS_NOSUID|syscall.MS_NODEV, opts); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("mount %s: %v", dir, err)
	}
	return os.NewFile(uintptr(fd), "/dev/fuse"), nil
}

func unmount(dir string) error {
	return syscall.Unmount(dir, 0)
}
