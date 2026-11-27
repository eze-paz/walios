package main

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// Raw DNS over connected UDP sockets: N queries in parallel goroutines (like Go's resolver,
// which sends A and AAAA at once), optionally with a ticker goroutine running.
func query(id int, wg *sync.WaitGroup) {
	defer wg.Done()
	q := []byte{0x12, byte(id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	t := time.Now()
	c, err := net.Dial("udp", "1.1.1.1:53")
	if err != nil {
		fmt.Println("dial", err)
		return
	}
	defer c.Close()
	c.Write(q)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 512)
	n, err := c.Read(b)
	fmt.Printf("q%d: n=%d err=%v %v\n", id, n, err, time.Since(t).Round(time.Millisecond))
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "t" {
		go func() {
			for range time.Tick(time.Second) {
			}
		}()
	}
	for round := 0; round < 2; round++ {
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go query(round*10+i, &wg)
		}
		wg.Wait()
	}
}
