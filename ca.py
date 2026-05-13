import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CA_KEY_PATH  = Path("certs/ca.key")
CA_CERT_PATH = Path("certs/ca.crt")

def generate_ca(common_name: str = "OTA Fleet CA"):
    key = Ed25519PrivateKey.generate()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Your Project"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                crl_sign=True, encipher_only=False, decipher_only=False
            ),
            critical=True
        )
        .sign(key, None)
    )
    CA_KEY_PATH.parent.mkdir(exist_ok=True)
    CA_KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
    )
    CA_KEY_PATH.chmod(0o400)
    CA_CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"CA generated.")
    print(f"Fingerprint: {cert.fingerprint(hashes.SHA256()).hex()}")

def load_ca():
    key = serialization.load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
    return key, cert

def sign_csr(csr_pem: bytes, serial: int, device_id: str) -> bytes:
    ca_key, ca_cert = load_ca()
    csr = x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid:
        raise ValueError("CSR signature invalid")
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(device_id)]),
            critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .sign(ca_key, None)
    )
    return cert.public_bytes(serialization.Encoding.PEM)
