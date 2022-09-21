---
aliases:
- /docs/agent/latest/flow/reference/cli/run
title: agent run
weight: 100
---

# `agent run` command

The `agent run` command runs Grafana Agent Flow in the foreground until an
interrupt is received.

## Usage

Usage: `agent run [flags] file`

`agent run` must be provided an argument which points at the River config file
to use. `agent run` will immediately exit with an error if the River file
wasn't specified, can't be loaded, or contained errors during the initial load.

Grafana Agent Flow will continue to run if subsequent reloads of the config
file fail, potentially marking components as unhealthy depending on the nature
of the failure. When this happens, Grafana Agent Flow will continue functioning
in the last valid state.

`agent run` launches an HTTP server for expose metrics about itself and
components. The HTTP server is also used for exposing a UI at `/` for debugging
running components.

The following flags are supported:

* `--server.http.listen-addr`: Address to listen for HTTP traffic on (default `127.0.0.1:12345`).
* `--server.http.ui-path-prefix`: Base path where the UI will be exposed (default `/`).
* `--storage.path`: Base directory where components can store data (default `data-agent/`).
* `--disable-reporting`: Disable [usage reporting][] of enabled [components][] to Grafana (default `false`).

[usage reporting]: {{< relref "../../../configuration/flags.md/#report-information-usage" >}}
[components]: {{< relref "../../concepts/components.md" >}}