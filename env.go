package main

import (
	"os"
	"strings"
)

// envFlag reports whether an environment variable is set to a true-ish value.
func envFlag(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "", "0", "false", "no", "off":
		return false
	}
	return true
}
