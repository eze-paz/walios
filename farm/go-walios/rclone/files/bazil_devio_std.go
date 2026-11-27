//go:build !(linux && wasm)

package fuse

import "syscall"

func devRead(c *Conn, b []byte) (int, error)  { return syscall.Read(c.fd(), b) }
func devWrite(c *Conn, b []byte) (int, error) { return syscall.Write(c.fd(), b) }
