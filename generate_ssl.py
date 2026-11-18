import os
import socket
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import ipaddress

def get_local_ip():
    """Retrieve local LAN IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't actually connect, just probes routing table
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def generate_self_signed_cert(cert_path="cert.pem", key_path="key.pem"):
    """
    Generate self-signed certificate with IP SANs for local LAN development.
    Required by mobile browsers to enable Web NFC (NDEFReader) over HTTPS.
    """
    local_ip = get_local_ip()
    print(f"Generating TLS certificate for local IP: {local_ip} and 127.0.0.1...")

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Cyber"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "QuantumShield"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QuantumShield Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, local_ip),
    ])

    san_list = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    if local_ip != "127.0.0.1":
        san_list.append(x509.IPAddress(ipaddress.IPv4Address(local_ip)))

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False,
    ).sign(key, hashes.SHA256())

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Certificate saved to {cert_path}")
    print(f"Private key saved to {key_path}")
    return cert_path, key_path, local_ip

if __name__ == "__main__":
    generate_self_signed_cert()
