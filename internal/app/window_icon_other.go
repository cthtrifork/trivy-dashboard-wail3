//go:build !linux || server

package app

import "github.com/wailsapp/wails/v3/pkg/application"

// SetWindowIcon is a no-op outside the Linux desktop build (other platforms take the icon from
// the bundle, server mode has no window).
func SetWindowIcon(*application.App, application.Window) {}
