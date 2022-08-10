#!/usr/bin/env python3
import os
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509

from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import univ
from pyasn1.codec.native.encoder import encode as native_encode
from pyasn1.codec.native.decoder import decode as native_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.der.decoder import decode as der_decode

from testca import TestCA


class InnerMessage(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "random",
            univ.OctetString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(32, 32)
            ),
        ),
        namedtype.NamedType("dhpub", univ.OctetString()),
        namedtype.OptionalNamedType("cert", univ.OctetString()),
    )


class OuterMessage(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("inner", univ.OctetString()),
        namedtype.OptionalNamedType("signature", univ.OctetString()),
    )


class DHKEX:
    side = None
    hash_algo = hashes.SHA256()

    def __init__(
        self, cert: x509.Certificate, privkey: rsa.RSAPrivateKey, ca: x509.Certificate
    ):
        self.cert = cert
        self.privkey = privkey
        self.ca = ca
        self.random = os.urandom(32)
        self.dh_privkey = x25519.X25519PrivateKey.generate()
        self.dh_pubkey = self.dh_privkey.public_key()
        self.client_hash = None
        self.server_hash = None
        self.shared_secret = None

    def exchange(self, other_pubkey: x25519.X25519PublicKey) -> bytes:
        assert other_pubkey != self.dh_pubkey
        self.shared_secret = self.dh_privkey.exchange(other_pubkey)

    def kdf_derive(self, info: bytes, length: int = 32):
        return HKDF(
            algorithm=self.hash_algo,
            length=length,
            salt=self.client_hash + self.server_hash,
            info=info,
        ).derive(self.shared_secret)

    def kdf_verify(self, info: bytes, message: bytes, length: int = 32):
        return HKDF(
            algorithm=self.hash_algo,
            length=length,
            salt=self.client_hash + self.server_hash,
            info=info,
        ).verify(self.shared_secret, message)

    def serialize_inner(self) -> bytes:
        dhpub = self.dh_pubkey.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        native = dict(random=self.random, dhpub=dhpub)
        if self.cert:
            cert = self.cert.public_bytes(serialization.Encoding.DER)
            native.update(cert=cert)
        asn1 = native_decode(native, InnerMessage())
        return der_encode(asn1)

    def serialize_outer(self, inner, sig):
        native = dict(inner=inner)
        if sig is not None:
            native.update(signature=sig)
        asn1 = native_decode(native, OuterMessage())
        return der_encode(asn1)

    def deserialize_inner(self, data: bytes):
        asn1, trail = der_decode(data, InnerMessage())
        if trail:
            raise ValueError(trail)
        native = native_encode(asn1)
        dh = x25519.X25519PublicKey.from_public_bytes(native["dhpub"])
        certder = native.get("cert")
        if certder is not None:
            cert = x509.load_der_x509_certificate(certder)
        else:
            cert = None
        return native["random"], dh, cert

    def deserialize_outer(self, data: bytes):
        asn1, trail = der_decode(data, OuterMessage())
        if trail:
            raise ValueError(trail)
        native = native_encode(asn1)
        return native["inner"], native.get("signature")

    def sign(self, message):
        if isinstance(self.privkey, rsa.RSAPrivateKey):
            return self.privkey.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(self.hash_algo),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                self.hash_algo,
            )
        else:
            return self.privkey.sign(message, ec.ECDSA(self.hash_algo))

    def verify(self, public_key, signature, message):
        if isinstance(self.privkey, rsa.RSAPrivateKey):
            return public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(self.hash_algo),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                self.hash_algo,
            )
        else:
            return public_key.verify(signature, message, ec.ECDSA(self.hash_algo))

    def hash(self, data: bytes) -> bytes:
        h = hashes.Hash(self.hash_algo)
        h.update(data)
        return h.finalize()

    def check_trust(self, cert: x509.Certificate):
        pubkey = self.ca.public_key()
        if isinstance(pubkey, rsa.RSAPublicKey):
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        else:
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )


class DHKEXClient(DHKEX):
    name = "client"

    def step1(self) -> bytes:
        client_inner = self.serialize_inner()
        self.client_hash = self.hash(client_inner)
        if self.cert is not None:
            client_sig = self.sign(client_inner)
        else:
            client_sig = None
        return self.serialize_outer(client_inner, client_sig)

    def step2(self, data: bytes) -> bytes:
        server_inner, server_sig = self.deserialize_outer(data)
        server_random, server_dhpub, server_cert = self.deserialize_inner(server_inner)
        self.check_trust(server_cert)
        self.verify(server_cert.public_key(), server_sig, server_inner)
        self.server_hash = self.hash(server_inner)
        self.exchange(server_dhpub)
        return self.kdf_derive(b"exchange verify")

    def hkdf_params(self):
        return self.hash()


class DHKEXServer(DHKEX):
    name = "server"

    def step1(self, data: bytes) -> bytes:
        client_inner, client_sig = self.deserialize_outer(data)
        client_random, client_dhpub, client_cert = self.deserialize_inner(client_inner)
        if client_cert is not None:
            self.check_trust(client_cert)
            self.verify(client_cert.public_key(), client_sig, client_inner)
        self.client_hash = self.hash(client_inner)

        server_inner = self.serialize_inner()
        server_sig = self.sign(server_inner)
        self.server_hash = self.hash(server_inner)
        self.exchange(client_dhpub)
        return self.serialize_outer(server_inner, server_sig)

    def step2(self, data: bytes):
        self.kdf_verify(b"exchange verify", data)


def demo():
    ca = TestCA()

    client = DHKEXClient(None, None, ca=ca.ca_cert)

    scert, sprivkey = ca.create_certkey_pair(DHKEXServer.name)
    server = DHKEXServer(scert, sprivkey, ca=ca.ca_cert)

    data1 = client.step1()
    data2 = server.step1(data1)
    data3 = client.step2(data2)
    server.step2(data3)  # optional

    print(client.kdf_derive(b"key"))
    print(server.kdf_derive(b"key"))

    ccert, cprivkey = ca.create_certkey_pair(DHKEXClient.name)
    client = DHKEXClient(ccert, cprivkey, ca=ca.ca_cert)
    server = DHKEXServer(scert, sprivkey, ca=ca.ca_cert)

    data1 = client.step1()
    data2 = server.step1(data1)
    data3 = client.step2(data2)
    server.step2(data3)  # optional

    print(client.kdf_derive(b"key"))
    print(server.kdf_derive(b"key"))


if __name__ == "__main__":
    demo()
