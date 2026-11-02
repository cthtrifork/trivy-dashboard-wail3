package main

import (
	"embed"
	"io/fs"
	"log"

	"github.com/cthtrifork/trivy-dashboard-wail3/internal/app"
	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	frontend, err := fs.Sub(assets, "frontend/dist")
	if err != nil {
		log.Fatal(err)
	}

	svc := app.NewScanService()
	wails := application.New(application.Options{
		Name:        "Trivy Scanner",
		Icon:        app.WindowIcon,
		Description: "Scan container images with Trivy running in Podman (" + app.Version() + ")",
		Services:    []application.Service{application.NewService(svc)},
		Assets:      application.AssetOptions{Handler: application.AssetFileServerFS(frontend), Middleware: app.AssetMiddleware},
		// Linux: GTK4 reports the application id as the window's Wayland app_id and X11 class, and
		// KDE/GNOME match it to the .desktop file of the same name (the launcher icon and grouping).
		// Keep it equal to the desktop file name and its StartupWMClass in build/linux.
		Linux: application.LinuxOptions{ApplicationID: "io.github.cthtrifork.trivy-scanner", ProgramName: "io.github.cthtrifork.trivy-scanner"},
	})
	// After New (an update restart re-launches this binary and New diverts it into the swap
	// helper) and before Run, as the Wails self-update tutorial prescribes.
	app.InitUpdater(svc, wails)

	window := wails.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:     "Trivy Scanner",
		Width:     1200,
		Height:    800,
		MinWidth:  800,
		MinHeight: 500,
		URL:       "/",
		Linux:     application.LinuxWindow{Icon: app.WindowIcon},
	})

	app.AddTray(wails, window)

	if err := wails.Run(); err != nil {
		log.Fatal(err)
	}
}
