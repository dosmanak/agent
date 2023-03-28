---
aliases:
- /docs/agent/latest/flow/reference/components/otelcol.processor.attributes
title: otelcol.processor.attributes
---

# otelcol.processor.attributes

`otelcol.processor.attributes` modifies attributes of a span, log, or metric.
It also supports the ability to filter and match input data to determine if 
they should be included or excluded for specified actions.

> **NOTE**: `otelcol.processor.attributes` is a wrapper over the upstream
> OpenTelemetry Collector `attributes` processor. Bug reports or feature requests
> will be redirected to the upstream repository, if necessary.
Multiple `otelcol.processor.attributes` components can be specified by giving them
different labels.

## Usage

```river
otelcol.processor.attributes "LABEL" {
	actions {
		action {
			key = "..."
			action = "..."
		}
    ...
  }
	match {
		include {
			match_type = "..."
            regexp {
                cacheenabled = bool
            }
			services = ["...", ...]
			span_names = ["...", ...]
			log_bodies = ["...", ...]
			log_severity_texts = ["...", ...]
			log_severity_number = "..."
			metric_names = ["...", ...]
			attributes = "..."
			resources = "..."
			libraries = "..."
			span_kinds = ["...", ...]
		}
		exclude {
			key = "..."
			action = "..."
		}
  }
}
```
## Arguments
`otelcol.processor.attributes` supports the following arguments:
Name | Type | Description | Default | Required
---- | ---- | ----------- | ------- | --------
`timeout` | `duration` | How long to wait before flushing the batch. | `"200ms"` | no
`send_batch_size` | `number` | Amount of data to buffer before flushing the batch. | `8192` | no
`send_batch_max_size` | `number` | Upper limit of a batch size. | `0` | no
`otelcol.processor.batch` accumulates data into a batch until one of the
following events happens:
* The duration specified by `timeout` elapses since the time the last batch was
  sent.
* The number of spans, log lines, or metric samples processed exceeds the
  number specified by `send_batch_size`.
Use `send_batch_max_size` to limit the amount of data contained in a single
batch. When set to `0`, batches can be any size.
For example, assume `send_batch_size` is set to the default `8192` and there
are currently 8000 batched spans. If the batch processor receives 8000 more
spans at once, the total batch size would be 16,192 which would then be flushed
as a single batch. `send_batch_max_size` constrains how big a batch can get.
When set to a non-zero value, `send_batch_max_size` must be greater or equal to
`send_batch_size`.
## Blocks
The following blocks are supported inside the definition of
`otelcol.processor.batch`:
Hierarchy | Block | Description | Required
--------- | ----- | ----------- | --------
output | [output][] | Configures where to send received telemetry data. | yes
[output]: #output-block
### match block
The following arguments are supported:
Name | Type | Description | Default | Required
---- | ---- | ----------- | ------- | --------
`match_type` | | | | 
`regexp` | | | | 
`services` | []string | | | 
`span_names` | []string | | | 
`log_bodies` | []string | | | 
`log_severity_texts` | []string | | | 
`log_severity_number` | | | | 
`metric_names` | []string | | | 
`attributes` | | | | 
`resources` | | | | 
`libraries` | | | | 
`span_kinds` | []string | | | 
### output block
{{< docs/shared lookup="flow/reference/components/output-block.md" source="agent" >}}
## Exported fields
The following fields are exported and can be referenced by other components:
Name | Type | Description
---- | ---- | -----------
`input` | `otelcol.Consumer` | A value that other components can use to send telemetry data to.
`input` accepts `otelcol.Consumer` data for any telemetry signal (metrics,
logs, or traces).
## Component health
`otelcol.processor.batch` is only reported as unhealthy if given an invalid
configuration.
## Debug information
`otelcol.processor.batch` does not expose any component-specific debug
information.
## Example
This example batches telemetry data before sending it to
[otelcol.exporter.otlp][] for further processing:
```river
otelcol.processor.batch "default" {
  output {
    metrics = [otelcol.exporter.otlp.production.input]
    logs    = [otelcol.exporter.otlp.production.input]
    traces  = [otelcol.exporter.otlp.production.input]
  }
}
otelcol.exporter.otlp "production" {
  client {
    endpoint = env("OTLP_SERVER_ENDPOINT")
  }
}
```
[otelcol.exporter.otlp]: {{< relref "./otelcol.exporter.otlp.md" >}}