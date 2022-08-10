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

from testca import TestCA


class DHKEX:
    side = None

    def __init__(
        self, cert: x509.Certificate, privkey: rsa.RSAPrivateKey, ca: x509.Certificate
    ):
        self.cert = cert
        # assumes both certs use same hash algos
        self.hash_algo = cert.signature_hash_algorithm
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
        dh = self.dh_pubkey.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        cert = self.cert.public_bytes(serialization.Encoding.DER)
        size = struct.pack("!H", len(cert))
        # TODO: better serialization format
        return self.random + dh + size + cert

    def serialize_outer(self, inner, sig):
        size = struct.pack("!H", len(inner))
        # TODO: better serialization format
        return size + inner + sig

    def deserialize_inner(self, data: bytes):
        random = data[:32]
        dh = x25519.X25519PublicKey.from_public_bytes(data[32:64])
        size = struct.unpack("!H", data[64:66])[0]
        cert = x509.load_der_x509_certificate(data[66 : 66 + size])
        return random, dh, cert

    def deserialize_outer(self, data: bytes):
        size = struct.unpack("!H", data[:2])[0]
        return data[2 : 2 + size], data[2 + size :]

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
        # client_inner_hash = self.hash(client_inner)
        client_sig = self.sign(client_inner)
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
    cert, privkey = ca.create_certkey_pair(DHKEXClient.name)
    client = DHKEXClient(cert, privkey, ca=ca.ca_cert)

    cert, privkey = ca.create_certkey_pair(DHKEXServer.name)
    server = DHKEXServer(cert, privkey, ca=ca.ca_cert)

    data1 = client.step1()
    data2 = server.step1(data1)
    data3 = client.step2(data2)
    # optional
    server.step2(data3)

    print(client.kdf_derive(b"key"))
    print(server.kdf_derive(b"key"))

    return client, server


if __name__ == "__main__":
    demo()
