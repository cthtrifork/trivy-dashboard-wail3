# Application lifecycle

How the app follows Wails' [Application Lifecycle](https://v3.wails.io/concepts/lifecycle/) guide, and where it
deliberately does not.

## The one real problem this fixed

Scans ran under `context.Background()` and the service had no `ServiceShutdown`, so **quitting mid-scan left the scan
running**. Measured in the native window against a stand-in `podman` that logs every call (closing the window with a
window manager, exactly like clicking ✕):

| | before | after |
|---|---|---|
| app exits | within the 0.1 s polling resolution | within the 0.1 s polling resolution |
| scan process left running | **1** | **0** |
| container removal requested | never | `podman rm --force --ignore --time 0 <name>` at once |
| signal to the `podman run` client | none | SIGTERM |

With real podman the leftover would have been a Trivy container still running (and possibly pulling an image) after the
app had gone: the guide's "don't leak resources". The **Cancel** button had the same flaw, because Go's default
cancellation is SIGKILL on the podman client, which gives podman no chance to stop the container.

## Stage by stage

| Guide | In this app |
|---|---|
| `ServiceStartup(ctx, …)`: "don't ignore the context" | keeps `ctx`; every scan, comparison and tag lookup derives from it |
| "The `ctx` is cancelled when shutdown begins" | so a quit cancels the running scan before any service shutdown code runs (verified in the beta.34 source: `shutdownServices` calls `cancel()` first) |
| `ServiceShutdown`: "always implement" | cancels a running scan and waits up to 1 s for its container to be removed; returns an error, which Wails logs, if it did not stop in time |
| "Keep shutdown fast (under 1 s)" | the wait is bounded (`shutdownGrace`), the container removal is bounded (5 s ceiling, normally instant), and the client gets a 3 s `WaitDelay` before a hard kill |
| "Don't block in service startup (under 2 s)" / "return errors to abort" | startup does nothing slow. It never aborts: a missing podman is shown in the UI, not by refusing to start |
| "Log lifecycle events" | `scan service: starting / quitting while a scan is running / stopped` through `app.Logger` |
| "Don't show dialogs in shutdown" | none |

How cancellation works (`PodmanEngine.RunTrivy`): each container gets a unique name (`trivy-scanner-<random>`). On
cancellation the container is removed **first**, then the podman client receives SIGTERM, and it is only killed if it
ignores that for 3 s. Removing by name matters because killing a `podman run` client does not reliably stop its container.

## Left out, on purpose

- **`ShouldQuit` confirmation ("a scan is running, quit anyway?").** Optional in the guide, and it would add a dialog on a
  path I could not test on GTK4 here. Quitting now cleans up reliably instead. It is easy to add if wanted.
- **`OnShutdown` / `PostShutdown`.** The guide prefers services for lifecycle work, and there is nothing else to flush:
  VEX assessments are written to disk, atomically, the moment they are saved.
- **Window hooks.** One window; Linux's default (quit when the last window closes) is what we want.

## Tests

- `internal/trivy/lifecycle_test.go` drives the real engine code with a stub `podman`: cancelling removes the named
  container and then signals the client with SIGTERM (not SIGKILL), every container gets its own name, and
  `CancelAndWait` waits for cleanup but gives up after its grace period instead of hanging shutdown.
- `internal/app/lifecycle_test.go` checks the service: a scan stops when the application context is cancelled,
  `ServiceShutdown` stops a running scan within budget, is instant when idle, and reports a scan that will not stop.

Not verified: real podman. This sandbox has none, so the behaviour of `podman rm --force --ignore --time 0` and of
podman's SIGTERM handling is taken from podman's documented behaviour, not observed.
