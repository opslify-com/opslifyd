package main

import (
	"embed"
	"io/fs"
)

// fsSub narrows the embedded filesystem to the cockpit directory, so paths in the
// SPA are rooted at "/" rather than "/cockpit/".
func fsSub(f embed.FS, dir string) (fs.FS, error) { return fs.Sub(f, dir) }
