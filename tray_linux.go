//go:build linux && !server

package main

import (
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/icons"
)

// addTray puts an icon in the StatusNotifier tray (GNOME needs an AppIndicator extension to
// show it). Closing the window still quits, so a scan is never left running unseen; the tray
// only brings the window back to the front and offers Quit.
func addTray(app *application.App, window application.Window) {
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
		SetIcon(icons.SystrayLight).
		SetDarkModeIcon(icons.SystrayDark).
		SetMenu(menu).
		OnClick(show)
}
