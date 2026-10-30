"""Count and bound the published SDK's real requests without recording credentials."""
import hashlib
import time

import httpx

from workspace_cases import MAX_ARTIFACT


class ResponseLimit(Exception):
    pass


class Transport(httpx.BaseTransport):
    def __init__(self, origin, observations, phase, inner=None):
        url = httpx.URL(origin)
        if url.scheme != 'http' or url.host != '127.0.0.1' or not url.port or url.path != '/' or url.query or url.userinfo:
            raise ValueError('SDK evaluations require the controller-owned loopback origin')
        self.origin = (url.scheme, url.host, url.port)
        self.observations, self.phase = observations, phase
        self.inner = inner if inner is not None else httpx.HTTPTransport(retries=0, trust_env=False)

    def handle_request(self, request):
        # Endpoint discovery must not forward the management or sandbox token elsewhere.
        if (request.url.scheme, request.url.host, request.url.port) != self.origin or request.url.userinfo:
            raise ValueError('SDK endpoint escaped the fixture origin')
        started = time.monotonic()
        row = {'phase': self.phase(), 'interface': 'opensandbox-python', 'method': request.method,
               'path': request.url.path, 'status': None}
        self.observations.append(row)
        response = None
        try:
            # The SDK disables its SSE read timeout. Bound that path too so a
            # stopped server cannot leave cleanup waiting on an unlimited read.
            timeouts = request.extensions.get('timeout', {})
            request.extensions['timeout'] = {name: min(timeouts.get(name) or 75, 75)
                                             for name in ('connect', 'read', 'write', 'pool')}
            response = self.inner.handle_request(request)
            row['status'] = response.status_code
            download = request.url.path.endswith('/files/download') and response.status_code == 200
            limit = MAX_ARTIFACT if download else 65536
            lengths = response.headers.get_list('content-length')
            encoding = response.headers.get('content-encoding', 'identity')
            if encoding != 'identity' or len(lengths) > 1 or (lengths and response.headers.get('transfer-encoding')):
                raise ValueError('Ambiguous SDK response framing')
            length = int(lengths[0]) if lengths and lengths[0].isascii() and lengths[0].isdigit() else None
            if (lengths and length is None) or (download and length is None):
                raise ValueError('SDK download requires one Content-Length')
            if length is not None and length > limit:
                raise ResponseLimit()
            data = bytearray()
            # Tools return complete command results. Buffer SSE within the same cap;
            # this client does not measure time to the first streamed output event.
            for chunk in response.stream:
                if len(data) + len(chunk) > limit:
                    raise ResponseLimit()
                if time.monotonic() - started > 90:
                    raise TimeoutError('SDK response deadline exceeded')
                data.extend(chunk)
            if length is not None and len(data) != length:
                raise ValueError('Incomplete SDK response')
            digest = hashlib.sha256(data).hexdigest()
            if download and response.headers.get('etag') != '"' + digest + '"':
                raise ValueError('SDK download digest did not match')
            row.update(bytes=len(data), sha256=digest)
            return httpx.Response(response.status_code, headers=response.headers, content=bytes(data), extensions=response.extensions)
        except Exception as error:
            row['error'] = 'response_limit' if isinstance(error, ResponseLimit) else type(error).__name__
            raise
        finally:
            if response is not None:
                response.close()
            row['seconds'] = round(time.monotonic() - started, 6)

    def close(self):
        self.inner.close()
