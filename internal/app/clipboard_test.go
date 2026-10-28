package app

import "testing"

// Without a running app (and always in server mode) there is no system
// clipboard, so CopyText must error and let the UI use the browser's.
func TestCopyTextWithoutNativeClipboard(t *testing.T) {
	if err := (&ScanService{}).CopyText("CVE-2024-3094"); err == nil {
		t.Fatal("CopyText with no app should return an error")
	}
}
