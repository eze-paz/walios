// rclone for walios: full build. cmd/all registers every stock command and backend
// (bisync, check, config, sync, lsjson, serve, s3/webdav/sftp/... backends); the wasm
// build tags keep the cgo ones (cmount) out on their own. Kept from the trimmed build:
// the dropbox/http/local imports are redundant under cmd/all but pin the sandpie backends.
package main

import (
	_ "github.com/rclone/rclone/backend/dropbox"
	_ "github.com/rclone/rclone/backend/http"
	_ "github.com/rclone/rclone/backend/local"
	"github.com/rclone/rclone/cmd"
	_ "github.com/rclone/rclone/cmd/all"
	_ "github.com/rclone/rclone/lib/plugin"
)

func main() { cmd.Main() }
