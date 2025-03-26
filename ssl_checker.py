import ssl
import socket
import binascii
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from datetime import datetime, UTC

def check_ssl_certificate_info(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        if response.status_code >= 400:
            return {"error": "Domain does not exist"}

        response = requests.get(f"https://{domain}", timeout=5)
        if response.status_code != 200:
            return {"error": "No SSL Certificate Used"}

        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(5)
        conn.connect((domain, 443))

        cert_der = conn.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        common_name = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value

        expiration_date = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")
        current_time = datetime.now(UTC)
        ssl_verified = cert.not_valid_after_utc > current_time

        try:
            san_extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = san_extension.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san = []

        serial_number = hex(cert.serial_number).upper()

        sha1_thumbprint = cert.fingerprint(hashes.SHA1())
        sha1_thumbprint_hex = binascii.hexlify(sha1_thumbprint).decode().upper()

        return {
            "common_name": common_name,
            "expiration_date": expiration_date,
            "ssl_verified": bool(ssl_verified),
            "subject_alternative_names": san,
            "serial_number": serial_number,
            "sha1_thumbprint": sha1_thumbprint_hex
        }

    except Exception as e:
        return {"error": str(e)}