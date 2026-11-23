// Package web holds the approval web app that phonekeyd serves.
package web

import "embed"

//go:embed index.html app.js sshsig.js ed25519.js vendor sw.js style.css manifest.webmanifest icon.svg icon-192.png icon-512.png
var FS embed.FS
