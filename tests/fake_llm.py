"""Tiny fake LLM provider for tests: Messages API, chat-completions, /v1/models."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class FakeLLM:
    def __init__(self):
        self.requests = []          # (path, headers, body)
        self.fail_first_429 = False
        self.coerce_to = None       # answer with this model id regardless of request
        self.reply = "OK"
        self.status = 200
        self.redirect_to = None
        self._429_sent = False
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj, extra=None):
                raw = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                outer.requests.append((self.path, dict(self.headers), None))
                if self.path == "/v1/models":
                    self._send(200, {"data": [
                        {"id": "anthropic.claude-sonnet-5-5"}, {"id": "deepseek.v3.2"},
                        {"id": "amazon.titan-embed-text-v2"}, {"id": "meta.llama4-70b"}]})
                elif self.path == "/feed":
                    self._send(200, {"items": ["Android WebView JS bridge abuse via addJavascriptInterface"]})
                else:
                    self._send(404, {"error": "nope"})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                outer.requests.append((self.path, dict(self.headers), body))
                if outer.redirect_to:
                    self.send_response(302)
                    self.send_header("Location", outer.redirect_to)
                    self.end_headers()
                    return
                if outer.fail_first_429 and not outer._429_sent:
                    outer._429_sent = True
                    self._send(429, {"error": "slow down"}, {"Retry-After": "0.1"})
                    return
                if outer.status != 200:
                    self._send(outer.status, {"error": {"message": "boom"}})
                    return
                model = outer.coerce_to or body.get("model")
                if self.path == "/v1/messages":
                    self._send(200, {"content": [{"type": "text", "text": outer.reply}],
                                     "model": model, "stop_reason": "end_turn",
                                     "usage": {"input_tokens": 1000, "output_tokens": 500}})
                elif self.path == "/v1/chat/completions":
                    self._send(200, {"choices": [{"message": {"content": outer.reply},
                                                  "finish_reason": "stop"}],
                                     "model": model, "usage": {"prompt_tokens": 1000,
                                                               "completion_tokens": 500}})
                else:
                    self._send(404, {"error": "nope"})

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=lambda: self.httpd.serve_forever(poll_interval=0.02), daemon=True).start()

    def close(self):
        self.httpd.shutdown()
