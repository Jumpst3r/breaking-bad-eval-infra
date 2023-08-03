import os
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from microsurf.utils.generators import SecretGenerator


class RSAPrivateKeyGen(SecretGenerator):
    """
    Generates RSA privat keys with DER encoding and PKCS1. 
        
        Args:
            keylen: The length of the private key in bits.
    """
    def __init__(self, keylen:int, nbTraces=8):
        super().__init__(keylen, asFile=True, nbTraces=nbTraces)
        self.keylen = keylen

    def __call__(self, *args, **kwargs) -> str:
        if self.index < self.nbTraces:
            self.key = rsa.generate_private_key(3, self.keylen)

            while self.key.private_numbers().public_numbers.n.bit_length() != self.keylen or self.key.private_numbers().d.bit_length() != self.keylen:
                self.key = rsa.generate_private_key(3, self.keylen)

            kbytes = self.key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            tempfile.tempdir = '/tmp'
            keyfile = tempfile.NamedTemporaryFile(prefix="microsurf_key_gen", suffix=".key").name
            with open(keyfile, 'wb') as f:
                f.write(kbytes)
            self.secrets.append((keyfile, self.key))
        secret = self.secrets[self.index % self.nbTraces][0]
        self.index += 1
        return secret

    def getSecret(self) -> int:
        return int(self.secrets[(self.index - 1) % self.nbTraces][1].private_numbers().p)
