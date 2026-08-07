from __future__ import annotations


class AiExecutionError(RuntimeError):
    safe_error = "gateway_error"


class GatewayUnavailable(AiExecutionError):
    safe_error = "gateway_unavailable"


class GatewayQueueFull(AiExecutionError):
    safe_error = "queue_full"


class GatewayDeadlineExceeded(AiExecutionError):
    safe_error = "queue_deadline_exceeded"


class GatewayMalformedResponse(AiExecutionError):
    safe_error = "malformed_gateway_response"


class GatewayShuttingDown(AiExecutionError):
    safe_error = "gateway_shutting_down"
