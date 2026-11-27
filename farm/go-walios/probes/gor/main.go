package main
import ("fmt"; "sync"; "time")
func main() { var wg sync.WaitGroup; t := time.Now(); for i := 0; i < 8; i++ { wg.Add(1); go func(i int) { defer wg.Done(); time.Sleep(50 * time.Millisecond) }(i) }; wg.Wait(); fmt.Println("8 goroutines x 50ms sleep took", time.Since(t).Round(time.Millisecond)) }
