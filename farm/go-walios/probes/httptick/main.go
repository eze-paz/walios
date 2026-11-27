package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// An HTTPS GET while another goroutine ticks every 10 ms (like rclone's accounting):
// the single-threaded linux/wasm scheduler must still poll the network.
func main() {
	url := "https://dl-cdn.alpinelinux.org/alpine/last-updated"
	if len(os.Args) > 1 {
		url = os.Args[1]
	}
	tick := len(os.Args) > 2
	if tick {
		go func() {
			for range time.Tick(10 * time.Millisecond) {
			}
		}()
	}
	t := time.Now()
	c := &http.Client{Timeout: 30 * time.Second}
	r, err := c.Get(url)
	if err != nil {
		fmt.Println("tick", tick, "err", err, time.Since(t).Round(time.Millisecond))
		return
	}
	b, _ := io.ReadAll(r.Body)
	fmt.Println("tick", tick, r.Status, len(b), time.Since(t).Round(time.Millisecond))
}
