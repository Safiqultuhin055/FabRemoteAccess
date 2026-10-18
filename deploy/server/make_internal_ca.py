"""Create an internal certificate authority and an HTTPS certificate for the Fabulous Remote server.

    python deploy/server/make_internal_ca.py --ip <server-ip> [--dns <host-name>] [--out deploy/server/certs]

Writes into the output folder:
    ca.crt / ca.cer   internal CA certificate (PEM / DER). Install ca.cer as a trusted root on client PCs.
    ca.key            internal CA private key. Keep it offline; it is needed only to issue new certificates.
    server.crt        server certificate (PEM) with the IP/DNS names as subjectAltName, signed by the CA.
    server.key        server private key (PEM). Readable only by the account that runs the server.

Running it again reuses the existing CA, so clients do not need to re-import anything when the
server certificate is renewed. Nothing here is committed: deploy/server/certs/ is git-ignored.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_DAYS = 3650
SERVER_DAYS = 825          # the maximum lifetime that clients generally accept


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def _write_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))


def load_or_create_ca(out: Path, name: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    ca_crt, ca_key = out / "ca.crt", out / "ca.key"
    if ca_crt.exists() and ca_key.exists():
        return (x509.load_pem_x509_certificate(ca_crt.read_bytes()),
                serialization.load_pem_private_key(ca_key.read_bytes(), password=None))
    key = _key()
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fabulous Remote"),
                         x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    _write_key(ca_key, key)
    ca_crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (out / "ca.cer").write_bytes(cert.public_bytes(serialization.Encoding.DER))
    return cert, key


def issue_server_certificate(out: Path, ca_cert, ca_key, ips: list[str], dns_names: list[str]) -> x509.Certificate:
    if not ips and not dns_names:
        raise ValueError("Give at least one --ip or --dns name for the server")
    names: list[x509.GeneralName] = [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]
    names += [x509.DNSName(name) for name in dns_names]
    key = _key()
    now = datetime.now(UTC)
    common_name = dns_names[0] if dns_names else ips[0]
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fabulous Remote"),
                                     x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=SERVER_DAYS))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=False,
                                         crl_sign=False, content_commitment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    _write_key(out / "server.key", key)
    (out / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ip", action="append", default=[], help="server IP address (repeatable)")
    parser.add_argument("--dns", action="append", default=[], help="server host name (repeatable)")
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "certs")
    parser.add_argument("--ca-name", default="Fabulous Remote Internal CA")
    args = parser.parse_args(argv)
    try:
        for ip in args.ip:
            ipaddress.ip_address(ip)
    except ValueError as exc:
        print(f"Invalid --ip: {exc}", file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    reused = (args.out / "ca.crt").exists()
    ca_cert, ca_key = load_or_create_ca(args.out, args.ca_name)
    try:
        cert = issue_server_certificate(args.out, ca_cert, ca_key, args.ip, args.dns)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"{'Reused' if reused else 'Created'} CA:  {args.out / 'ca.crt'}  (clients import {args.out / 'ca.cer'})")
    print(f"Server cert: {args.out / 'server.crt'}  valid until {cert.not_valid_after_utc:%Y-%m-%d} for "
          f"{', '.join(args.ip + args.dns)}")
    print(f"Server key:  {args.out / 'server.key'}  (restrict access; never share)")
    print(f"CA key:      {args.out / 'ca.key'}  (move offline after use)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
