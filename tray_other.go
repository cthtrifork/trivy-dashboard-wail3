//go:build !linux || server

package main

import "github.com/wailsapp/wails/v3/pkg/application"

// addTray is a no-op: only the Linux desktop build has a tray icon.
func addTray(*application.App, application.Window) {}
