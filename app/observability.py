"""Low-cardinality process metrics and request logs without evidence or credentials."""

import json
import logging
import time
import uuid
from collections import defaultdict
from threading import Lock

from starlette.datastructures import MutableHeaders

logger = logging.getLogger("identitytrace.requests")
logger.setLevel(logging.INFO)
if not logger.handlers:
    logger.addHandler(logging.StreamHandler())
logger.propagate = False


class RequestMetrics:
    def __init__(self):
        self.lock = Lock()
        self.counts = defaultdict(int)
        self.seconds = defaultdict(float)

    def record(self, method, route, status, duration):
        with self.lock:
            key = (method, route, str(status))
            self.counts[key] += 1
            self.seconds[key] += duration

    def render(self):
        lines = ["# TYPE identitytrace_http_requests_total counter",
                 "# TYPE identitytrace_http_request_duration_seconds_sum counter"]
        with self.lock:
            for (method, route, status), count in sorted(self.counts.items()):
                labels = f'method={json.dumps(method)},route={json.dumps(route)},status={json.dumps(status)}'
                lines.append(f"identitytrace_http_requests_total{{{labels}}} {count}")
                lines.append(f"identitytrace_http_request_duration_seconds_sum{{{labels}}} {self.seconds[(method, route, status)]:.6f}")
        return "\n".join(lines) + "\n"


class ObservabilityMiddleware:
    def __init__(self, app, metrics):
        self.app, self.metrics = app, metrics

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request_id = uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        started = time.monotonic()
        status = 500

        async def wrapped_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = request_id
                headers["Cache-Control"] = "no-store"
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                if scope.get("scheme") == "https":
                    headers["Strict-Transport-Security"] = "max-age=31536000"
            await send(message)

        try:
            await self.app(scope, receive, wrapped_send)
        finally:
            duration = time.monotonic() - started
            route = getattr(scope.get("route"), "path", "unmatched")
            if route != "unmatched" and scope["path"].startswith("/api/") and not route.startswith("/api/"):
                route = "/api" + route
            method = scope["method"] if scope["method"] in {"GET", "POST", "PATCH", "PUT", "DELETE", "HEAD", "OPTIONS"} else "OTHER"
            self.metrics.record(method, route, status, duration)
            logger.info(json.dumps({"event": "http.request", "request_id": request_id,
                                    "method": method, "route": route, "status": status,
                                    "duration_ms": round(duration * 1000, 2)}))
