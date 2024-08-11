from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
import ssl

def _name2dict(name):
    ret = {
        "rfc4514": name.rfc4514_string(),
        "attrs": {}
    }
    for a in name:
        ret["attrs"][a.oid._name] = ret.get(a.oid._name, []) + [a.value]
    return ret

def dump_certificate(server, port):
    certificate = ssl.get_server_certificate((server, port))
    cert = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
    data = {
        "version": [cert.version.name, cert.version.value],
        "issuer": _name2dict(cert.issuer),
        "subject": _name2dict(cert.subject),
        "valid_after": cert.not_valid_before_utc.isoformat()[:19],
        "valid_before": cert.not_valid_after_utc.isoformat()[:19],
        "public_key": cert.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH).decode(),
        "dns_names": [],
        "raw": "".join(certificate.split("\n")[1:-2])
    }

    try:
        data["dns_names"] = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except:
        pass

    return data
