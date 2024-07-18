import tempfile
from xmlrpc.client import boolean

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from microsurf.utils.generators import SecretGenerator

class HaclRSAGen(SecretGenerator):
    """
    Generates all types of keys for haclstar with PEM encoding and PKCS8. 
    """

    def __init__(self, keylen: int, nbTraces=8):
        super().__init__(keylen, asFile=True, nbTraces=nbTraces)

    def __call__(self, *args, **kwargs) -> str:
        if self.index < self.nbTraces:
            tempfile.tempdir = '/tmp'
            keyfile = tempfile.NamedTemporaryFile(
                prefix="microsurf_key_gen", suffix=".key").name
            with open(keyfile, 'wb') as f:
                self.key = rsa.generate_private_key(3, self.keylen)

                while self.key.private_numbers().public_numbers.n.bit_length() != self.keylen or self.key.private_numbers().d.bit_length() != self.keylen:
                    self.key = rsa.generate_private_key(3, self.keylen)

                print(f"n = {self.key.private_numbers().public_numbers.n:#x}")
                print(f"e = {self.key.private_numbers().public_numbers.e:#x}")
                print(f"d = {self.key.private_numbers().d:#x}")

                f.write((self.key.private_numbers().public_numbers.n).to_bytes(64, byteorder='big', signed=False))
                f.write((self.key.private_numbers().public_numbers.e).to_bytes(64, byteorder='big', signed=False))
                f.write((self.key.private_numbers().d).to_bytes(64, byteorder='big', signed=False))

            # only append the last key
            # TODO: we should probably append all keys
            self.secrets.append((keyfile, self.key))
        secret = self.secrets[self.index % self.nbTraces][0]
        self.index += 1
        return secret

    def getSecret(self) -> int:
        return self.secrets[(self.index - 1) % self.nbTraces][1].private_numbers().d
