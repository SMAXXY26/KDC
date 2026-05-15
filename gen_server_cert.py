from pathlib import Path
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ca import load_ca

CERTS_DIR = Path("certs")

def gen_server_cert():
    print("Loading CA...")
    ca_key, ca_cert = load_ca()

    print("Generating server key...")
    server_key = Ed25519PrivateKey.generate()

    print("Building server certificate...")
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ota-server"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("ota-server.local"),
            ]),
            critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .sign(ca_key, None)
    )

    server_key_path = CERTS_DIR / "server.key"
    server_key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
    )
    server_key_path.chmod(0o400)

    server_cert_path = CERTS_DIR / "server.crt"
    server_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print("Server certificate written.")
    print(f"  Key:  {server_key_path}")
    print(f"  Cert: {server_cert_path}")
    print(f"  Expires: {cert.not_valid_after_utc.date()}")

if __name__ == "__main__":
    gen_server_cert()