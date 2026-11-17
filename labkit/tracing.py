"""
Shared OpenTelemetry setup: every lab process exports spans to Jaeger over OTLP/HTTP.

    from labkit.tracing import setup_tracing
    tracer = setup_tracing("helpdesk-server")

The MCP SDK does the rest: the client injects `traceparent` into each request's
`_meta` (SEP-414) and the server's default middleware continues the trace, so
agent -> gateway -> server spans land in one trace.
"""
import atexit

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

OTLP_ENDPOINT = "http://127.0.0.1:4318/v1/traces"   # Jaeger


def setup_tracing(service_name: str) -> trace.Tracer:
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=OTLP_ENDPOINT)))
    trace.set_tracer_provider(provider)
    atexit.register(provider.shutdown)   # flush spans on exit
    return trace.get_tracer(service_name)
