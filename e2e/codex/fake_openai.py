import http.server, socketserver, re, sys, json, datetime

# Local fake OpenAI upstream for the Codex e2e. Captures whatever the proxy
# forwarded (so we can assert PII was masked on egress) and returns a valid
# Responses-API SSE stream that echoes back any sordino tokens it saw (so the
# proxy's unmask-on-ingress path is exercised end to end).
#
# Codex (>=0.140) only speaks the Responses wire API and aborts unless the
# stream ends in a well-formed `response.completed`, so we emit the full event
# sequence a real codex client accepts, not the 3-event minimum the Rust
# integration test uses.

PORT = int(sys.argv[1])
CAP = sys.argv[2]
TOK = re.compile(r"\[[A-Z0-9_]+_[0-9a-f]{12}\]")


def sse(events):
    out = ""
    for ev, data in events:
        out += "event: %s\ndata: %s\n\n" % (ev, json.dumps(data))
    return out.encode()


def responses_stream(body):
    toks = list(dict.fromkeys(TOK.findall(body)))
    text = "Acknowledged. " + ("Echo: " + " ".join(toks) if toks else "(no tokens seen)")
    rid = "resp_e2e"
    msg = {
        "id": "msg_1", "type": "message", "status": "completed", "role": "assistant",
        "content": [{"type": "output_text", "text": text, "annotations": []}],
    }
    base = {"id": rid, "object": "response", "model": "gpt-e2e", "status": "in_progress",
            "output": [], "usage": None}
    completed = dict(base); completed["status"] = "completed"; completed["output"] = [msg]
    completed["usage"] = {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}
    return sse([
        ("response.created", {"type": "response.created", "sequence_number": 0, "response": base}),
        ("response.in_progress", {"type": "response.in_progress", "sequence_number": 1, "response": base}),
        ("response.output_item.added", {"type": "response.output_item.added", "sequence_number": 2,
            "output_index": 0, "item": {"id": "msg_1", "type": "message", "status": "in_progress",
            "role": "assistant", "content": []}}),
        ("response.content_part.added", {"type": "response.content_part.added", "sequence_number": 3,
            "item_id": "msg_1", "output_index": 0, "content_index": 0,
            "part": {"type": "output_text", "text": "", "annotations": []}}),
        ("response.output_text.delta", {"type": "response.output_text.delta", "sequence_number": 4,
            "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": text}),
        ("response.output_text.done", {"type": "response.output_text.done", "sequence_number": 5,
            "item_id": "msg_1", "output_index": 0, "content_index": 0, "text": text}),
        ("response.content_part.done", {"type": "response.content_part.done", "sequence_number": 6,
            "item_id": "msg_1", "output_index": 0, "content_index": 0,
            "part": {"type": "output_text", "text": text, "annotations": []}}),
        ("response.output_item.done", {"type": "response.output_item.done", "sequence_number": 7,
            "output_index": 0, "item": msg}),
        ("response.completed", {"type": "response.completed", "sequence_number": 8, "response": completed}),
    ])


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("content-length", "0") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        with open(CAP, "a") as f:
            f.write("\n===== %s POST %s =====\n" % (datetime.datetime.now().isoformat(), self.path))
            f.write("AUTH=%s\n" % ("yes" if (self.headers.get("authorization") or self.headers.get("x-api-key")) else "no"))
            f.write(body + "\n")
        if self.path.startswith("/v1/responses") or self.path.endswith("/responses"):
            self._send(200, "text/event-stream", responses_stream(body))
            return
        self._send(200, "application/json", b"{}")

    def do_GET(self):
        self._send(200, "application/json", b"{}")

    def log_message(self, *a):
        pass


socketserver.TCPServer.allow_reuse_address = True
with socketserver.ThreadingTCPServer(("127.0.0.1", PORT), H) as srv:
    srv.serve_forever()
