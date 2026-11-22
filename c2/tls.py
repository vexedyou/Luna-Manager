"""Self-signed listener certificate generation and fingerprint reporting.

The implant pins the SHA-256 of this certificate (baked in at build time), so the
listener can rotate its key material without a CA. Regenerate with
`--rotate-cert` and rebuild implants afterwards.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def fingerprint(pem_path: str) -> str:
    with open(pem_path, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def ensure_cert(directory: str, common_name: str = "luna") -> tuple[str, str]:
    os.makedirs(directory, exist_ok=True)
    cert_path = os.path.join(directory, "listener.crt.pem")
    key_path = os.path.join(directory, "listener.key.pem")
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Luna Lab"),
        ]
    )
    started = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(started - _dt.timedelta(minutes=5))
        .not_valid_after(started + _dt.timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(common_name),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("0.0.0.0")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    with open(key_path, "wb") as fh:
        fh.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.chmod(key_path, 0o600)
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path
