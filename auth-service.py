"""
Mock auth service: JWT → STS credential exchange.

Validates the incoming JWT against jwt-public-key.pem (RS256), then returns
hard-coded S3 credentials that match the s3proxy configuration so Spark S3A
can read from the proxy without touching real AWS.

Endpoint
--------
POST /v1/credentials/sts
  Authorization: Bearer <jwt>

  → 200 {"accessKeyId": ..., "secretAccessKey": ..., "sessionToken": ...}
  → 401 {"error": ...}

Usage
-----
    uv run python auth-service.py
    # or
    python auth-service.py
"""

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from flask import Flask, jsonify, request

app = Flask(__name__)

PUBLIC_KEY_PATH = "jwt-public-key.pem"

with open(PUBLIC_KEY_PATH, "rb") as f:
    _public_key = load_pem_public_key(f.read())

# Credentials returned to Spark — must match S3PROXY_IDENTITY / S3PROXY_CREDENTIAL
# in docker-compose.s3proxy.yml.
_STS_CREDENTIALS = {
    "accessKeyId": "test-access-key-id",
    "secretAccessKey": "test-secret-access-key",
    "sessionToken": "test-session-token",
}


@app.route("/v1/credentials/sts", methods=["POST"])
def sts_credentials():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    token = auth_header.removeprefix("Bearer ")

    try:
        claims = jwt.decode(
            token,
            _public_key,
            algorithms=["RS256"],
            options={"verify_aud": False},
        )
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "JWT has expired"}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({"error": f"Invalid JWT: {e}"}), 401

    app.logger.info(
        "Issuing STS credentials for sub=%s email=%s",
        claims.get("sub"),
        claims.get("email"),
    )
    return jsonify(_STS_CREDENTIALS)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=True)