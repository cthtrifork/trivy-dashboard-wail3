//go:build linux && !server

package app

import (
	_ "embed"

	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed tray_icon.png
var trayIcon []byte

// AddTray puts an icon in the StatusNotifier tray (GNOME needs an AppIndicator extension to
// show it). Closing the window still quits, so a scan is never left running unseen; the tray
// only brings the window back to the front and offers Quit.
func AddTray(app *application.App, window application.Window) {
	show := func() {
		if window.IsMinimised() {
			window.UnMinimise()
		}
		window.Show().Focus()
	}

	menu := app.NewMenu()
	menu.Add("Show Trivy Scanner").OnClick(func(*application.Context) { show() })
	menu.AddSeparator()
	menu.Add("Quit").OnClick(func(*application.Context) { app.Quit() })

	app.SystemTray.New().
		SetIcon(trayIcon).
		SetMenu(menu).
		OnClick(show)
}
