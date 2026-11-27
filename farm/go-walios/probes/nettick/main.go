package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"
)

// Where does time go with a busy ticker goroutine: DNS, TCP connect or the TLS handshake?
func main() {
	host := "dl-cdn.alpinelinux.org"
	if len(os.Args) > 2 {
		d, _ := time.ParseDuration(os.Args[2])
		go func() {
			for range time.Tick(d) {
			}
		}()
	}
	if len(os.Args) > 1 && os.Args[1] != "x" {
		host = os.Args[1]
	}
	t := time.Now()
	addrs, err := net.DefaultResolver.LookupHost(context.Background(), host)
	fmt.Println("dns", addrs, err, time.Since(t).Round(time.Millisecond))
	if err != nil {
		return
	}
	t = time.Now()
	c, err := net.DialTimeout("tcp", net.JoinHostPort(addrs[0], "443"), 10*time.Second)
	fmt.Println("tcp", err, time.Since(t).Round(time.Millisecond))
	if err != nil {
		return
	}
	t = time.Now()
	tc := tls.Client(c, &tls.Config{ServerName: host})
	err = tc.Handshake()
	fmt.Println("tls", err, time.Since(t).Round(time.Millisecond))
}
