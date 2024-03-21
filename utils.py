
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def b64_url(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip("=")



key_path = "key.pem"
cert_path = "cert.pem"


def gen_key_cert(domains):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "ZH"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Zurich"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "acme-netsec"),
        x509.NameAttribute(NameOID.COMMON_NAME, "acme-netsec"),
    ])).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain)
                                     for domain in domains]),
        critical=False,
    ).sign(key, hashes.SHA256())

    der = csr.public_bytes(serialization.Encoding.DER)

    return key, csr, der


def write_cert(key, certificate,key_path,cert_path):
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_path, "wb") as f:
        f.write(certificate)