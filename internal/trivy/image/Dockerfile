# The Trivy image the app runs scans with. This file is the single source of truth for the
# default version: it is embedded into the binary (internal/trivy/engine.go) and Dependabot's
# docker ecosystem keeps the tag current (.github/dependabot.yml). It is never built.
# Override at run time with TRIVY_SCANNER_TRIVY_IMAGE.
FROM docker.io/aquasec/trivy:0.76.1
