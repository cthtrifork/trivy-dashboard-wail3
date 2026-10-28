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
		Assets:      application.AssetOptions{Handler: application.AssetFileServerFS(frontend)},
		// Linux: the program name is the window's app_id/WM_CLASS, which the packaged
		// trivy-scanner.desktop (StartupWMClass) matches for the launcher icon and grouping.
		Linux: application.LinuxOptions{ProgramName: "trivy-scanner"},
	})

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
