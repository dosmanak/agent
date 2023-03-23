package attributes_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-kit/log/level"
	"github.com/grafana/agent/component/otelcol"
	"github.com/grafana/agent/component/otelcol/internal/fakeconsumer"
	"github.com/grafana/agent/component/otelcol/processor/attributes"
	"github.com/grafana/agent/pkg/flow/componenttest"
	"github.com/grafana/agent/pkg/river"
	"github.com/grafana/agent/pkg/util"
	"github.com/grafana/dskit/backoff"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/attributesprocessor"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// A lot of the TestDecode tests were inspired by tests in the Otel repo:
// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.63.0/processor/attributesprocessor/testdata/config.yaml

func TestDecode1(t *testing.T) {
	cfg := `
		actions {
			action {
				key = "attribute1"
				value = 123
				action = "insert"
			}
			action {
				key = "string key"
				value = "anotherkey"
				action = "insert"
			}
		}

		output {
			// no-op: will be overridden by test code.
		}
	`
	var args attributes.Arguments
	require.NoError(t, river.Unmarshal([]byte(cfg), &args))

	convertedArgs, err := args.Convert()
	require.NoError(t, err)
	otelObj := (convertedArgs).(*attributesprocessor.Config)

	action := &otelObj.Actions[0]
	require.Equal(t, "attribute1", action.Key)
	require.Equal(t, 123, action.Value)
	require.Equal(t, "insert", string(action.Action))

	action = &otelObj.Actions[1]
	require.Equal(t, "string key", action.Key)
	require.Equal(t, "anotherkey", action.Value)
	require.Equal(t, "insert", string(action.Action))
}

func TestDecode2(t *testing.T) {
	cfg := `
		actions {
			action {
				key = "http.url"
				pattern = "^(?P<http_protocol>.*):\\/\\/(?P<http_domain>.*)\\/(?P<http_path>.*)(\\?|\\&)(?P<http_query_params>.*)"
				action = "extract"
			}
		}

		output {
			// no-op: will be overridden by test code.
		}
	`
	var args attributes.Arguments
	require.NoError(t, river.Unmarshal([]byte(cfg), &args))

	convertedArgs, err := args.Convert()
	require.NoError(t, err)
	otelObj := (convertedArgs).(*attributesprocessor.Config)

	action := &otelObj.Actions[0]
	require.Equal(t, "http.url", action.Key)
	require.Equal(t, "^(?P<http_protocol>.*):\\/\\/(?P<http_domain>.*)\\/(?P<http_path>.*)(\\?|\\&)(?P<http_query_params>.*)", action.RegexPattern)
	require.Equal(t, "extract", string(action.Action))
}

func TestDecode3(t *testing.T) {
	cfg := `
		actions {
			action {
				key = "boo"
				from_attribute = "foo"
				action = "update"
			}
			action {
				key = "db.secret"
				value = "redacted"
				action = "update"
			}
		}

		output {
			// no-op: will be overridden by test code.
		}
	`
	var args attributes.Arguments
	require.NoError(t, river.Unmarshal([]byte(cfg), &args))

	convertedArgs, err := args.Convert()
	require.NoError(t, err)
	otelObj := (convertedArgs).(*attributesprocessor.Config)

	action := &otelObj.Actions[0]
	require.Equal(t, "boo", action.Key)
	require.Equal(t, "foo", action.FromAttribute)
	require.Equal(t, "update", string(action.Action))

	action = &otelObj.Actions[1]
	require.Equal(t, "db.secret", action.Key)
	require.Equal(t, "redacted", action.Value)
	require.Equal(t, "update", string(action.Action))
}

func TestDecode4(t *testing.T) {
	cfg := `
	exclude {
		match_type = "strict"
		resources {
			key = "host.type"
			value = "n1-standard-1"
		}
	}
	actions {
		action {
			key = "credit_card"
			action = "delete"
		}
		action {
			key = "duplicate_key"
			action = "delete"
		}
	}

	output {
		// no-op: will be overridden by test code.
	}
	`
	var args attributes.Arguments
	require.NoError(t, river.Unmarshal([]byte(cfg), &args))

	convertedArgs, err := args.Convert()
	require.NoError(t, err)
	otelObj := (convertedArgs).(*attributesprocessor.Config)

	require.NotNil(t, otelObj.Exclude)

	res := &otelObj.Exclude.Resources[0]
	require.Equal(t, "strict", string(otelObj.Exclude.MatchType))

	require.Equal(t, "host.type", res.Key)
	require.Equal(t, "n1-standard-1", res.Value)

	action := &otelObj.Actions[0]
	require.Equal(t, "credit_card", action.Key)
	require.Equal(t, "delete", string(action.Action))

	action = &otelObj.Actions[1]
	require.Equal(t, "duplicate_key", action.Key)
	require.Equal(t, "delete", string(action.Action))
}

func TestDecode5(t *testing.T) {
	cfg := `
	exclude {
		match_type = "strict"
		libraries {
			name = "mongo-java-driver"
			version = "3.8.0"
		}
	}
	actions {
		action {
			key = "credit_card"
			action = "delete"
		}
		action {
			key = "duplicate_key"
			action = "delete"
		}
	}

	output {
		// no-op: will be overridden by test code.
	}
	`
	var args attributes.Arguments
	require.NoError(t, river.Unmarshal([]byte(cfg), &args))

	convertedArgs, err := args.Convert()
	require.NoError(t, err)
	otelObj := (convertedArgs).(*attributesprocessor.Config)

	require.NotNil(t, otelObj.Exclude)
	require.Equal(t, "strict", string(otelObj.Exclude.MatchType))

	lib := &otelObj.Exclude.Libraries[0]
	require.Equal(t, "mongo-java-driver", lib.Name)
	require.Equal(t, "3.8.0", *lib.Version)

	action := &otelObj.Actions[0]
	require.Equal(t, "credit_card", action.Key)
	require.Equal(t, "delete", string(action.Action))

	action = &otelObj.Actions[1]
	require.Equal(t, "duplicate_key", action.Key)
	require.Equal(t, "delete", string(action.Action))
}

func TestDecode6(t *testing.T) {
	cfg := `
	exclude {
		match_type = "regexp"
		services = ["auth.*", "login.*"]
	}
	actions {
		action {
			key = "credit_card"
			action = "delete"
		}
		action {
			key = "duplicate_key"
			action = "delete"
		}
	}

	output {
		// no-op: will be overridden by test code.
	}
	`
	var args attributes.Arguments
	require.NoError(t, river.Unmarshal([]byte(cfg), &args))

	convertedArgs, err := args.Convert()
	require.NoError(t, err)
	otelObj := (convertedArgs).(*attributesprocessor.Config)

	require.NotNil(t, otelObj.Exclude)
	require.Equal(t, "regexp", string(otelObj.Exclude.MatchType))

	svc := &otelObj.Exclude.Services
	require.Equal(t, "auth.*", (*svc)[0])
	require.Equal(t, "login.*", (*svc)[1])

	action := &otelObj.Actions[0]
	require.Equal(t, "credit_card", action.Key)
	require.Equal(t, "delete", string(action.Action))

	action = &otelObj.Actions[1]
	require.Equal(t, "duplicate_key", action.Key)
	require.Equal(t, "delete", string(action.Action))
}

func TestDecode7(t *testing.T) {
	cfg := `
	exclude {
		match_type = "regexp"
		services = ["auth.*", "login.*"]
	}
	actions {
		action {
			key = "credit_card"
			action = "delete"
		}
		action {
			key = "duplicate_key"
			action = "delete"
		}
	}

	output {
		// no-op: will be overridden by test code.
	}
	`
	var args attributes.Arguments
	require.NoError(t, river.Unmarshal([]byte(cfg), &args))

	convertedArgs, err := args.Convert()
	require.NoError(t, err)
	otelObj := (convertedArgs).(*attributesprocessor.Config)

	require.NotNil(t, otelObj.Exclude)
	require.Equal(t, "regexp", string(otelObj.Exclude.MatchType))

	svc := &otelObj.Exclude.Services
	require.Equal(t, "auth.*", (*svc)[0])
	require.Equal(t, "login.*", (*svc)[1])

	action := &otelObj.Actions[0]
	require.Equal(t, "credit_card", action.Key)
	require.Equal(t, "delete", string(action.Action))

	action = &otelObj.Actions[1]
	require.Equal(t, "duplicate_key", action.Key)
	require.Equal(t, "delete", string(action.Action))
}

func TestDecode8(t *testing.T) {
	cfg := `
	include {
		match_type = "strict"
		services = ["svcA", "svcB"]
	}
	exclude {
		match_type = "strict"
		attributes {
			key = "redact_trace"
			value = false
		}
	}
	actions {
		action {
			key = "credit_card"
			action = "delete"
		}
		action {
			key = "duplicate_key"
			action = "delete"
		}
	}

	output {
		// no-op: will be overridden by test code.
	}
	`
	var args attributes.Arguments
	require.NoError(t, river.Unmarshal([]byte(cfg), &args))

	convertedArgs, err := args.Convert()
	require.NoError(t, err)
	otelObj := (convertedArgs).(*attributesprocessor.Config)

	require.NotNil(t, otelObj.Include)
	require.Equal(t, "strict", string(otelObj.Include.MatchType))

	svc := &otelObj.Include.Services
	require.Equal(t, "svcA", (*svc)[0])
	require.Equal(t, "svcB", (*svc)[1])

	require.NotNil(t, otelObj.Exclude)
	require.Equal(t, "strict", string(otelObj.Exclude.MatchType))

	attr := &otelObj.Exclude.Attributes[0]
	require.Equal(t, "redact_trace", attr.Key)
	require.Equal(t, false, attr.Value)

	action := &otelObj.Actions[0]
	require.Equal(t, "credit_card", action.Key)
	require.Equal(t, "delete", string(action.Action))

	action = &otelObj.Actions[1]
	require.Equal(t, "duplicate_key", action.Key)
	require.Equal(t, "delete", string(action.Action))
}

func TestDecode9(t *testing.T) {
	cfg := `
	actions {
		action {
			key = "operation"
			value = "default"
			action = "insert"
		}
		action {
			key = "svc.operation"
			value = "operation"
			action = "upsert"
		}
		action {
			key = "operation"
			action = "delete"
		}
	}

	output {
		// no-op: will be overridden by test code.
	}
	`
	var args attributes.Arguments
	require.NoError(t, river.Unmarshal([]byte(cfg), &args))

	convertedArgs, err := args.Convert()
	require.NoError(t, err)
	otelObj := (convertedArgs).(*attributesprocessor.Config)

	action := &otelObj.Actions[0]
	require.Equal(t, "operation", action.Key)
	require.Equal(t, "default", action.Value)
	require.Equal(t, "insert", string(action.Action))

	action = &otelObj.Actions[1]
	require.Equal(t, "svc.operation", action.Key)
	require.Equal(t, "operation", action.Value)
	require.Equal(t, "upsert", string(action.Action))

	action = &otelObj.Actions[2]
	require.Equal(t, "operation", action.Key)
	require.Equal(t, "delete", string(action.Action))
}

func TestDecode10(t *testing.T) {
	cfg := `
	actions {
		action {
			key = "db.table"
			action = "delete"
		}
		action {
			key = "redacted_span"
			value = true
			action = "upsert"
		}
		action {
			key = "copy_key"
			from_attribute = "key_original"
			action = "update"
		}
		action {
			key = "account_id"
			value = 2245
			action = "insert"
		}
		action {
			key = "account_password"
			action = "delete"
		}
	}

	output {
		// no-op: will be overridden by test code.
	}
	`
	var args attributes.Arguments
	require.NoError(t, river.Unmarshal([]byte(cfg), &args))

	convertedArgs, err := args.Convert()
	require.NoError(t, err)
	otelObj := (convertedArgs).(*attributesprocessor.Config)

	action := &otelObj.Actions[0]
	require.Equal(t, "db.table", action.Key)
	require.Equal(t, "delete", string(action.Action))

	action = &otelObj.Actions[1]
	require.Equal(t, "redacted_span", action.Key)
	require.Equal(t, true, action.Value)
	require.Equal(t, "upsert", string(action.Action))

	action = &otelObj.Actions[2]
	require.Equal(t, "copy_key", action.Key)
	require.Equal(t, "key_original", action.FromAttribute)
	require.Equal(t, "update", string(action.Action))

	action = &otelObj.Actions[3]
	require.Equal(t, "account_id", action.Key)
	require.Equal(t, 2245, otelObj.Actions[3].Value)
	require.Equal(t, "insert", string(action.Action))

	action = &otelObj.Actions[4]
	require.Equal(t, "account_password", action.Key)
	require.Equal(t, "delete", string(action.Action))
}

func TestDecode11(t *testing.T) {
	cfg := `
	include {
		match_type = "regexp"
		services = ["auth.*"]
	}
	exclude {
		match_type = "regexp"
		span_names = ["login.*"]
	}
	actions {
		action {
			key = "password"
			action = "update"
			value = "obfuscated"
		}
		action {
			key = "token"
			action = "delete"
		}
	}

	output {
		// no-op: will be overridden by test code.
	}
	`
	var args attributes.Arguments
	require.NoError(t, river.Unmarshal([]byte(cfg), &args))

	convertedArgs, err := args.Convert()
	require.NoError(t, err)
	otelObj := (convertedArgs).(*attributesprocessor.Config)

	require.NotNil(t, otelObj.Include)
	require.Equal(t, "regexp", string(otelObj.Include.MatchType))
	require.Equal(t, "auth.*", otelObj.Include.Services[0])

	require.NotNil(t, otelObj.Exclude)
	require.Equal(t, "regexp", string(otelObj.Exclude.MatchType))
	require.Equal(t, "login.*", otelObj.Exclude.SpanNames[0])

	action := &otelObj.Actions[0]
	require.Equal(t, "password", action.Key)
	require.Equal(t, "obfuscated", action.Value)
	require.Equal(t, "update", string(action.Action))

	action = &otelObj.Actions[1]
	require.Equal(t, "token", action.Key)
	require.Equal(t, "delete", string(action.Action))
}

func TestDecode12(t *testing.T) {
	cfg := `
	include {
		match_type = "regexp"
		attributes {
			key = "env"
			value = "SELECT \\* FROM USERS.*"
		}
	}
	actions {
		action {
			key = "db.statement"
			action = "update"
			value = "SELECT * FROM USERS [obfuscated]"
		}
	}

	output {
		// no-op: will be overridden by test code.
	}
	`
	var args attributes.Arguments
	require.NoError(t, river.Unmarshal([]byte(cfg), &args))

	convertedArgs, err := args.Convert()
	require.NoError(t, err)
	otelObj := (convertedArgs).(*attributesprocessor.Config)

	require.NotNil(t, otelObj.Include)
	require.Equal(t, "regexp", string(otelObj.Include.MatchType))

	attr := &otelObj.Include.Attributes[0]
	require.Equal(t, "env", attr.Key)
	require.Equal(t, "SELECT \\* FROM USERS.*", attr.Value)

	action := &otelObj.Actions[0]
	require.Equal(t, "db.statement", action.Key)
	require.Equal(t, "SELECT * FROM USERS [obfuscated]", action.Value)
	require.Equal(t, "update", string(action.Action))
}

func TestDecode13(t *testing.T) {
	cfg := `
	include {
		match_type = "regexp"
		log_bodies = ["AUTH.*"]
	}
	actions {
		action {
			key = "password"
			action = "update"
			value = "obfuscated"
		}
		action {
			key = "token"
			action = "delete"
		}
	}

	output {
		// no-op: will be overridden by test code.
	}
	`
	var args attributes.Arguments
	require.NoError(t, river.Unmarshal([]byte(cfg), &args))

	convertedArgs, err := args.Convert()
	require.NoError(t, err)
	otelObj := (convertedArgs).(*attributesprocessor.Config)

	require.NotNil(t, otelObj.Include)
	require.Equal(t, "regexp", string(otelObj.Include.MatchType))

	require.Equal(t, "AUTH.*", otelObj.Include.LogBodies[0])

	action := &otelObj.Actions[0]
	require.Equal(t, "password", action.Key)
	require.Equal(t, "obfuscated", action.Value)
	require.Equal(t, "update", string(action.Action))

	action = &otelObj.Actions[1]
	require.Equal(t, "token", otelObj.Actions[1].Key)
	require.Equal(t, "delete", string(action.Action))
}

func TestDecode14(t *testing.T) {
	cfg := `
	include {
		match_type = "regexp"
		log_severity_texts = ["debug.*"]
	}
	actions {
		action {
			key = "password"
			action = "update"
			value = "obfuscated"
		}
		action {
			key = "token"
			action = "delete"
		}
	}

	output {
		// no-op: will be overridden by test code.
	}
	`
	var args attributes.Arguments
	require.NoError(t, river.Unmarshal([]byte(cfg), &args))

	convertedArgs, err := args.Convert()
	require.NoError(t, err)
	otelObj := (convertedArgs).(*attributesprocessor.Config)

	require.NotNil(t, otelObj.Include)
	require.Equal(t, "regexp", string(otelObj.Include.MatchType))

	require.Equal(t, "debug.*", otelObj.Include.LogSeverityTexts[0])

	action := &otelObj.Actions[0]
	require.Equal(t, "password", action.Key)
	require.Equal(t, "obfuscated", action.Value)
	require.Equal(t, "update", string(action.Action))

	action = &otelObj.Actions[1]
	require.Equal(t, "token", otelObj.Actions[1].Key)
	require.Equal(t, "delete", string(action.Action))
}

func TestDecode15(t *testing.T) {
	cfg := `
	actions {
		action {
			key = "origin"
			from_context = "metadata.origin"
			action = "insert"
		}
		action {
			key = "enduser.id"
			from_context = "auth.subject"
			action = "insert"
		}
	}

	output {
		// no-op: will be overridden by test code.
	}
	`
	var args attributes.Arguments
	require.NoError(t, river.Unmarshal([]byte(cfg), &args))

	convertedArgs, err := args.Convert()
	require.NoError(t, err)

	otelObj := (convertedArgs).(*attributesprocessor.Config)

	action := &otelObj.Actions[0]
	require.Equal(t, "origin", action.Key)
	require.Equal(t, "metadata.origin", action.FromContext)
	require.Equal(t, "insert", string(action.Action))

	action = &otelObj.Actions[1]
	require.Equal(t, "enduser.id", action.Key)
	require.Equal(t, "auth.subject", action.FromContext)
	require.Equal(t, "insert", string(action.Action))
}

func TestRun(t *testing.T) {
	ctx := componenttest.TestContext(t)
	l := util.TestLogger(t)

	ctrl, err := componenttest.NewControllerFromID(l, "otelcol.processor.attributes")
	require.NoError(t, err)

	cfg := `
		actions {
			action {
				key = "attribute1"
				value = 123
				action = "insert"
			}
			action {
				key = "string key"
				value = "anotherkey"
				action = "insert"
			}
		}

		output {
			// no-op: will be overridden by test code.
		}
	`
	var args attributes.Arguments
	require.NoError(t, river.Unmarshal([]byte(cfg), &args))

	// Override our arguments so traces get forwarded to traceCh.
	traceCh := make(chan ptrace.Traces)
	args.Output = makeTracesOutput(traceCh)

	go func() {
		err := ctrl.Run(ctx, args)
		require.NoError(t, err)
	}()

	require.NoError(t, ctrl.WaitRunning(time.Second), "component never started")
	require.NoError(t, ctrl.WaitExports(time.Second), "component never exported anything")

	// Send traces in the background to our processor.
	go func() {
		exports := ctrl.Exports().(otelcol.ConsumerExports)

		bo := backoff.New(ctx, backoff.Config{
			MinBackoff: 10 * time.Millisecond,
			MaxBackoff: 100 * time.Millisecond,
		})
		for bo.Ongoing() {
			err := exports.Input.ConsumeTraces(ctx, createTestTraces())
			if err != nil {
				level.Error(l).Log("msg", "failed to send traces", "err", err)
				bo.Wait()
				continue
			}

			return
		}
	}()

	//TODO: Try changing actual attributes, just to sanity checks that everything works?

	// Wait for our processor to finish and forward data to traceCh.
	select {
	case <-time.After(time.Second):
		require.FailNow(t, "failed waiting for traces")
	case tr := <-traceCh:
		require.Equal(t, 1, tr.SpanCount())
	}
}

//TODO: makeTracesOutput and createTestTraces were copied from other tests. Import them from a common go file?

// makeTracesOutput returns ConsumerArguments which will forward traces to the
// provided channel.
func makeTracesOutput(ch chan ptrace.Traces) *otelcol.ConsumerArguments {
	traceConsumer := fakeconsumer.Consumer{
		ConsumeTracesFunc: func(ctx context.Context, t ptrace.Traces) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case ch <- t:
				return nil
			}
		},
	}

	return &otelcol.ConsumerArguments{
		Traces: []otelcol.Consumer{&traceConsumer},
	}
}

func createTestTraces() ptrace.Traces {
	// Matches format from the protobuf definition:
	// https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/trace/v1/trace.proto
	var bb = `{
		"resource_spans": [{
			"scope_spans": [{
				"spans": [{
					"name": "TestSpan"
				}]
			}]
		}]
	}`

	decoder := &ptrace.JSONUnmarshaler{}
	data, err := decoder.UnmarshalTraces([]byte(bb))
	if err != nil {
		panic(err)
	}
	return data
}
