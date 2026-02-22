"""
Generate a persistent RSA-2048 keypair and mint a JWT signed by the private key.

Run this once to create jwt-private-key.pem and jwt-public-key.pem.
Both files are committed to the repo so the server and client use the same key.

    uv run python create-jwt-token.py
    # or
    python create-jwt-token.py
"""

import datetime
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate an RSA-2048 keypair and persist both halves.
# In production the keypair comes from your IdP (Dex, Okta, etc.).
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

with open("jwt-private-key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))

with open("jwt-public-key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

print("Keypair written: jwt-private-key.pem, jwt-public-key.pem")

# Mint a JWT signed by the private key
now = datetime.datetime.utcnow()
payload = {
    "iss": "http://localhost:5556/dex",
    "sub": "user-001",
    "email": "dataengineer@example.com",
    "aud": "spark-client",
    "iat": now,
    "exp": now + datetime.timedelta(hours=24),
}

token = jwt.encode(payload, private_key, algorithm="RS256")
print(token)