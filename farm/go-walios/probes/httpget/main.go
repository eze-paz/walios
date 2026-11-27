package main
import ("fmt"; "io"; "net/http")
func main() { r, err := http.Get("https://api.dropboxapi.com/2/check/app"); fmt.Println("get", err); if r != nil { b, _ := io.ReadAll(r.Body); fmt.Println(r.Status, len(b)) } }
