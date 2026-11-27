package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"
)

var t0 = time.Now()

func ts() string { return time.Since(t0).Round(time.Millisecond).String() }

type logConn struct {
	*net.UDPConn
	id int
}

func (c logConn) Write(b []byte) (int, error) {
	n, err := c.UDPConn.Write(b)
	fmt.Println(ts(), "conn", c.id, "write", n, err)
	return n, err
}
func (c logConn) Read(b []byte) (int, error) {
	fmt.Println(ts(), "conn", c.id, "read start")
	n, err := c.UDPConn.Read(b)
	fmt.Println(ts(), "conn", c.id, "read", n, err)
	return n, err
}
func (c logConn) SetDeadline(t time.Time) error {
	fmt.Println(ts(), "conn", c.id, "deadline in", time.Until(t).Round(time.Millisecond))
	return c.UDPConn.SetDeadline(t)
}

func main() {
	if len(os.Args) > 1 {
		go func() {
			for range time.Tick(time.Second) {
			}
		}()
	}
	n := 0
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		n++
		dl, ok := ctx.Deadline()
		fmt.Println(ts(), "dial", n, network, address, "ctx deadline", ok, time.Until(dl).Round(time.Millisecond))
		var d net.Dialer
		c, err := d.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return logConn{c.(*net.UDPConn), n}, nil
	}}
	a, err := r.LookupHost(context.Background(), "example.com")
	fmt.Println(ts(), "result", a, err)
}
