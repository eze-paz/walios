package main
import ("fmt"; "os"; "runtime")
func main() { fmt.Println("hello from go", runtime.Version(), runtime.GOOS, runtime.GOARCH, "args", os.Args[1:], "HOME", os.Getenv("HOME")); wd, err := os.Getwd(); fmt.Println("cwd", wd, err) }
