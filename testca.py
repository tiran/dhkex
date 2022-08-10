import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID


class TestCA:
    # based on freeipa ipatests/create_external_ca.py
    ISSUER_CN = "CA dhkex test"

    def __init__(self, days=365):
        self.now = datetime.datetime.utcnow()
        self.delta = datetime.timedelta(days=days)
        self.ca_key = self.create_key()
        self.ca_public_key = self.ca_key.public_key()
        self.issuer = self.create_name(self.ISSUER_CN)
        self.ca_cert = self.create_ca()

    def create_key(self):
        if False:
            return rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
        else:
            return ec.generate_private_key(ec.SECP384R1())

    def create_name(self, cn: str):
        return x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ]
        )

    def _create_cert(self, subject, public_key, is_ca=False):
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(self.issuer)
        builder = builder.public_key(public_key)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(self.now)
        builder = builder.not_valid_after(self.now + self.delta)

        if is_ca:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
        else:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )

        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_public_key),
            critical=False,
        )

        return builder.sign(self.ca_key, hashes.SHA384())

    def create_ca(self):
        return self._create_cert(self.issuer, self.ca_public_key, is_ca=True)

    def create_certkey_pair(self, cn):
        key = self.create_key()
        public_key = key.public_key()
        cert = self._create_cert(self.create_name(cn), public_key, is_ca=False)
        return cert, key
