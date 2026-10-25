//go:build !linux

package main

// childrenRSS is only implemented on Linux; elsewhere the webview's memory is not reported.
func childrenRSS() int64 { return -1 }
