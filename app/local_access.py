"""Keep the development scanner accessible only through local, same-origin APIs."""

from ipaddress import ip_address
from urllib.parse import urlsplit

from starlette.responses import JSONResponse


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def authority(value):
    try:
        if "@" in value:
            return None
        parsed = urlsplit("http://" + value)
        if parsed.path or parsed.query or parsed.fragment or parsed.hostname not in LOCAL_HOSTS:
            return None
        return parsed.hostname, parsed.port or 80
    except ValueError:
        return None


class LocalOnlyMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        host = authority(headers.get(b"host", b"").decode("latin-1"))
        peer = scope.get("client")
        try:
            local_peer = bool(peer and ip_address(peer[0]).is_loopback)
        except ValueError:
            local_peer = False
        message = None
        code = 403
        if not host:
            message, code = "Use localhost or a loopback address to open this scanner.", 400
        elif not local_peer:
            message = "This scanner accepts local connections only."
        if not message and scope["path"].startswith("/api/"):
            origin = headers.get(b"origin")
            if origin:
                try:
                    parsed = urlsplit(origin.decode("latin-1"))
                    origin_host = authority(parsed.netloc) if parsed.scheme in {"http", "https"} else None
                    valid_origin = not (parsed.path or parsed.query or parsed.fragment) and origin_host == host and parsed.scheme == scope.get("scheme", "http")
                except ValueError:
                    valid_origin = False
                if not valid_origin:
                    message = "API requests must come from this scanner's own page."
            if headers.get(b"sec-fetch-site") == b"cross-site":
                message = "Cross-site API requests are not allowed. Open the scanner directly."
        if message:
            return await JSONResponse({"detail": message}, status_code=code)(scope, receive, send)

        async def private_send(event):
            if event["type"] == "http.response.start" and scope["path"].startswith("/api/"):
                event = {**event, "headers": [*event.get("headers", []), (b"cache-control", b"no-store")]}
            await send(event)
        await self.app(scope, receive, private_send)
