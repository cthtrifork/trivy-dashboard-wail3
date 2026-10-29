package app

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func assetHandler() http.Handler {
	fsys := fstest.MapFS{
		"index.html":    {Data: []byte("<!doctype html><title>x</title>" + strings.Repeat("a", 2000))},
		"assets/a-1.js": {Data: []byte(strings.Repeat("var a=1;", 500))},
		"logo.png":      {Data: []byte("\x89PNG\r\n\x1a\n" + strings.Repeat("x", 500))},
	}
	return ServeAssets(http.FileServerFS(fsys))
}

func get(t *testing.T, path string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	assetHandler().ServeHTTP(rec, req)
	return rec
}

func TestServeAssetsGzipsText(t *testing.T) {
	rec := get(t, "/assets/a-1.js", map[string]string{"Accept-Encoding": "gzip, br"})
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", rec.Header().Get("Content-Encoding"))
	}
	if rec.Header().Get("Content-Length") != "" {
		t.Error("Content-Length must be dropped for a compressed body")
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(zr)
	if string(body) != strings.Repeat("var a=1;", 500) {
		t.Error("decompressed body differs from the file")
	}
}

func TestServeAssetsPassThrough(t *testing.T) {
	for name, tc := range map[string]struct {
		path string
		hdr  map[string]string
	}{
		"no accept-encoding": {"/assets/a-1.js", nil},
		"binary":             {"/logo.png", map[string]string{"Accept-Encoding": "gzip"}},
		"range":              {"/assets/a-1.js", map[string]string{"Accept-Encoding": "gzip", "Range": "bytes=0-9"}},
		"not found":          {"/missing.js", map[string]string{"Accept-Encoding": "gzip"}},
	} {
		t.Run(name, func(t *testing.T) {
			if enc := get(t, tc.path, tc.hdr).Header().Get("Content-Encoding"); enc != "" {
				t.Errorf("Content-Encoding = %q, want none", enc)
			}
		})
	}
}

func TestServeAssetsCacheHeaders(t *testing.T) {
	if cc := get(t, "/assets/a-1.js", nil).Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("hashed asset Cache-Control = %q, want immutable", cc)
	}
	if cc := get(t, "/index.html", nil).Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("index Cache-Control = %q, want no-cache", cc)
	}
}
