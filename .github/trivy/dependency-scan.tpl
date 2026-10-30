{{- /* Markdown report for the "Dependency scan" PR comment. Input is the list of Trivy results. */ -}}
{{- $found := false -}}
## Trivy dependency scan
{{ range . }}{{ if .Vulnerabilities }}{{ $found = true }}
### `{{ .Target }}`

| Severity | Package | Version | Fixed in | Advisory |
|---|---|---|---|---|
{{ range .Vulnerabilities -}}
| {{ .Severity }} | `{{ .PkgName }}` | {{ .InstalledVersion }} | {{ if .FixedVersion }}{{ .FixedVersion }}{{ else }}–{{ end }} | {{ if .PrimaryURL }}[{{ .VulnerabilityID }}]({{ .PrimaryURL }}){{ else }}{{ .VulnerabilityID }}{{ end }} |
{{ end }}
{{ end }}{{ end -}}
{{ if not $found }}
No vulnerabilities found.
{{ end }}
