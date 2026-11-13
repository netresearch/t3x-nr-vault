"""Stand-in for the Kubernetes TokenReview API, used by the HashiCorp functional tests.

Vault's Kubernetes auth method does not trust the service account token on its
own: it posts it to the cluster API and believes the answer. This server gives
one fixed answer, "authenticated as system:serviceaccount:typo3:web", so a real
Vault can be exercised end to end without a cluster. It is a test fixture and
must never run anywhere else.
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

REVIEW = {
    "apiVersion": "authentication.k8s.io/v1",
    "kind": "TokenReview",
    "status": {
        "authenticated": True,
        "user": {
            "username": "system:serviceaccount:typo3:web",
            "uid": "11111111-2222-3333-4444-555555555555",
            "groups": [
                "system:serviceaccounts",
                "system:serviceaccounts:typo3",
                "system:authenticated",
            ],
        },
    },
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = json.dumps(REVIEW).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
