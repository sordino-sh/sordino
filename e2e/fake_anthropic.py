import http.server, socketserver, re, sys, json, datetime

PORT = int(sys.argv[1])
CAP = sys.argv[2]
TOK = re.compile(r"\[[A-Z0-9_]+_[0-9a-f]{12}\]")


def sse_bytes(tokens):
    text = "Acknowledged. " + ("Echo: " + " ".join(tokens) if tokens else "(no tokens seen)")
    frames = [
        ("message_start", {"type": "message_start", "message": {
            "id": "msg_e2e", "type": "message", "role": "assistant", "model": "claude-e2e",
            "content": [], "stop_reason": None, "stop_sequence": None,
            "usage": {"input_tokens": 10, "output_tokens": 1}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0,
            "content_block": {"type": "text", "text": ""}}),
        ("ping", {"type": "ping"}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": text}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": None},
            "usage": {"input_tokens": 10, "output_tokens": 20}}),
        ("message_stop", {"type": "message_stop"}),
    ]
    out = ""
    for ev, data in frames:
        out += "event: %s\ndata: %s\n\n" % (ev, json.dumps(data))
    return out.encode()


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
        if self.path.startswith("/v1/messages/count_tokens"):
            self._send(200, "application/json", json.dumps({"input_tokens": 12}).encode())
            return
        if self.path.startswith("/v1/messages"):
            toks = list(dict.fromkeys(TOK.findall(body)))
            self._send(200, "text/event-stream", sse_bytes(toks))
            return
        self._send(200, "application/json", b"{}")

    def do_GET(self):
        self._send(200, "application/json", b"{}")

    def log_message(self, *a):
        pass


socketserver.TCPServer.allow_reuse_address = True
with socketserver.ThreadingTCPServer(("127.0.0.1", PORT), H) as srv:
    srv.serve_forever()
