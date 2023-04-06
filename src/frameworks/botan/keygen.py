import os
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519, rsa

from microsurf.utils.generators import SecretGenerator


class BotanGenerator(SecretGenerator):
    """
    Generates all types of keys for botan with PEM encoding and PKCS8. 

        Args:
            keylen: Unused.
    """

    def __init__(self, keylen: int, type='p256', nbTraces=8):
        self.type = type
        super().__init__(keylen, asFile=True, nbTraces=nbTraces)

    def __call__(self, *args, **kwargs) -> str:
        if self.index < self.nbTraces:
            tempfile.tempdir = '/tmp'
            keyfile = tempfile.NamedTemporaryFile(
                prefix="microsurf_key_gen", suffix=".key").name
            with open(keyfile, 'wb') as f:
                for i in range(2):
                    if self.type == 'x25519':
                        self.key = x25519.X25519PrivateKey.generate()
                    elif self.type == 'p256':
                        self.key = ec.generate_private_key(ec.SECP256R1())
                    elif self.type == 'rsa':
                        self.key = rsa.generate_private_key(3, 512)
                    else:
                        raise "Unsupported secret type"
                    kbytes = self.key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )

                    f.write(kbytes)

            # only append the last key
            # TODO: we should probably append all keys
            self.secrets.append((keyfile, self.key))
        secret = self.secrets[self.index % self.nbTraces][0]
        self.index += 1
        return secret

    def getSecret(self) -> int:
        if self.type == 'p256':
            return self.secrets[(self.index - 1) % self.nbTraces][1].private_numbers().private_value
        elif self.type == 'x25519':
            return int.from_bytes(self.secrets[(self.index - 1) % self.nbTraces][1].private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ), 'big')
        elif self.type == 'rsa':
            return int.from_bytes(self.secrets[(self.index - 1) % self.nbTraces][1].private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ), 'big')
