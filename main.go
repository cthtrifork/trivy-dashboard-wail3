package main

import (
	"embed"
	"io/fs"
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// version is stamped at release time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	frontend, err := fs.Sub(assets, "frontend/dist")
	if err != nil {
		log.Fatal(err)
	}

	svc := NewScanService()
	app := application.New(application.Options{
		Name:        "Trivy Scanner",
		Description: "Scan container images with Trivy running in Podman (" + version + ")",
		Services:    []application.Service{application.NewService(svc)},
		Assets:      application.AssetOptions{Handler: application.AssetFileServerFS(frontend)},
	})
	// After New (an update restart re-launches this binary and New diverts it into the swap
	// helper) and before Run, as the Wails self-update tutorial prescribes.
	svc.initUpdater(app)

	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:     "Trivy Scanner",
		Width:     1200,
		Height:    800,
		MinWidth:  800,
		MinHeight: 500,
		URL:       "/",
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
