# The Trivy image the app runs scans with. This file is the single source of truth for the
# default version: it is embedded into the binary (internal/trivy/engine.go) and Dependabot's
# docker ecosystem keeps the tag current (.github/dependabot.yml). It is never built.
# The user can override it per scan with the "Trivy version or image" option in the UI.
FROM docker.io/aquasec/trivy:0.76.1
