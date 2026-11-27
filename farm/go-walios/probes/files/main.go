package main
import ("fmt"; "os"; "path/filepath")
func main() {
  d := os.TempDir(); if len(os.Args) > 1 { d = os.Args[1] }
  p := filepath.Join(d, "go-spike.txt")
  fmt.Println("write", os.WriteFile(p, []byte("x"), 0644))
  fmt.Println("rename", os.Rename(p, p+".2"))
  es, err := os.ReadDir(d); fmt.Println("readdir", len(es), err)
  b, err := os.ReadFile(p + ".2"); fmt.Println("read", string(b), err)
  fmt.Println("remove", os.Remove(p+".2"))
}
