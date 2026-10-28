//go:build linux && !server

package app

/*
#cgo pkg-config: gtk4
#include <stdlib.h>
#include <gtk/gtk.h>

static void setWindowIcon(const char *dir, const char *name, void *window) {
	GdkDisplay *display = gdk_display_get_default();
	if (display == NULL) {
		return;
	}
	gtk_icon_theme_add_search_path(gtk_icon_theme_get_for_display(display), dir);
	gtk_window_set_default_icon_name(name);
	if (window != NULL) {
		gtk_window_set_icon_name(GTK_WINDOW(window), name);
	}
}
*/
import "C"

import (
	_ "embed"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

const windowIconName = "trivy-scanner"

//go:embed window_icon.png
var windowIcon []byte

// SetWindowIcon gives the window the app icon (the same art as frontend/public/favicon.svg).
// GTK4 has no API to set a window icon from bytes, only by name from the icon theme, so the
// PNG is written to the user cache dir, which is added to the theme's search path. A packaged
// install already has the icon in hicolor and this is a harmless duplicate. Best effort: any
// failure leaves the desktop's default icon.
func SetWindowIcon(app *application.App, window application.Window) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return
	}
	dir = filepath.Join(dir, "trivy-scanner", "icons")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	if err := os.WriteFile(filepath.Join(dir, windowIconName+".png"), windowIcon, 0o644); err != nil {
		return
	}
	app.Event.OnApplicationEvent(events.Linux.ApplicationStartup, func(*application.ApplicationEvent) {
		application.InvokeSync(func() {
			cdir, cname := C.CString(dir), C.CString(windowIconName)
			defer C.free(unsafe.Pointer(cdir))
			defer C.free(unsafe.Pointer(cname))
			C.setWindowIcon(cdir, cname, window.NativeWindow())
		})
	})
}
