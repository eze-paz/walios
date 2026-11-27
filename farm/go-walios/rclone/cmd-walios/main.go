// rclone for walios: the backends and commands the sandpie mount plan needs.
package main

import (
	_ "github.com/rclone/rclone/backend/dropbox"
	_ "github.com/rclone/rclone/backend/http"
	_ "github.com/rclone/rclone/backend/local"
	"github.com/rclone/rclone/cmd"
	_ "github.com/rclone/rclone/cmd/cat"
	_ "github.com/rclone/rclone/cmd/copy"
	_ "github.com/rclone/rclone/cmd/ls"
	_ "github.com/rclone/rclone/cmd/lsf"
	_ "github.com/rclone/rclone/cmd/mount"
	_ "github.com/rclone/rclone/cmd/version"
	_ "github.com/rclone/rclone/lib/plugin"
)

func main() { cmd.Main() }
