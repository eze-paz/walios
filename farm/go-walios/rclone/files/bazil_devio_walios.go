//go:build linux && wasm

package fuse

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// /dev/fuse I/O through the *os.File (netpoller), keeping bazil's raw-errno contract.
func devRead(c *Conn, b []byte) (int, error) {
	n, err := c.dev.Read(b)
	return n, rawErr(err)
}

func devWrite(c *Conn, b []byte) (int, error) {
	n, err := c.dev.Write(b)
	return n, rawErr(err)
}

func rawErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
		return syscall.ENODEV // unmounted
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
