package main
import ("fmt"; "net"; "time")
func main() { c, err := net.DialTimeout("tcp", "example.com:80", 10*time.Second); fmt.Println("dial", err); if c == nil { return }; fmt.Fprintf(c, "HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n"); b := make([]byte, 64); n, err := c.Read(b); fmt.Printf("read %q %v\n", b[:n], err) }
