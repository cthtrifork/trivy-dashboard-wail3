{{- /* One Markdown list item per finding. The workflow sorts the lines and diffs base against PR. */ -}}
{{- range . }}{{ range .Vulnerabilities -}}
- {{ .Severity }} [{{ .VulnerabilityID }}](https://avd.aquasec.com/nvd/{{ .VulnerabilityID | lower }}) `{{ .PkgName }}` {{ .InstalledVersion }}
{{ end }}{{ end -}}
