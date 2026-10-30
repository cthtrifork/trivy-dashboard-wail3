{{- /* One line per finding: id, package, installed version, severity. The workflow sorts and diffs these. */ -}}
{{- range . }}{{ range .Vulnerabilities -}}
{{ .VulnerabilityID }}	{{ .PkgName }}	{{ .InstalledVersion }}	{{ .Severity }}
{{ end }}{{ end -}}
