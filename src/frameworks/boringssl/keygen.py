import os
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

from microsurf.utils.generators import SecretGenerator


class SECP256PrivateKeyGeneratorBoringSSL(SecretGenerator):
    """
    Generates EC privat keys with DER encoding and PKCS8 (SECP256K1). 
        
        Args:
            keylen: The length of the private key in bits.
    """
    def __init__(self, keylen:int, nbTraces=8):
        super().__init__(keylen, asFile=True, nbTraces=nbTraces)

    def __call__(self, *args, **kwargs) -> str:
        if self.index < self.nbTraces:
            self.pkey =  ec.generate_private_key(ec.SECP256R1())
            kbytes = self.pkey.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            tempfile.tempdir = '/tmp'
            keyfile = tempfile.NamedTemporaryFile(prefix="microsurf_key_gen", suffix=".key").name
            with open(keyfile, 'wb') as f:
                f.write(kbytes)
            self.secrets.append((keyfile, self.pkey))
        secret = self.secrets[self.index % self.nbTraces][0]
        self.index += 1
        return secret

    def getSecret(self) -> int:
        return self.secrets[(self.index - 1) % self.nbTraces][1].private_numbers().private_value

class ECDHP256PrivateKeyGeneratorBoringSSL(SecretGenerator):
    """
    Generates TWO EC privat keys with DER encoding and PKCS8 (p256). 
        
        Args:
            keylen: The length of the private key in bits.
    """
    def __init__(self, keylen:int, type='p256', nbTraces=8):
        self.type = type
        super().__init__(keylen, asFile=True, nbTraces=nbTraces)
        

    def __call__(self, *args, **kwargs) -> str:
        if self.index < self.nbTraces:
            if self.type == 'x25519':
                self.pkey1 =  x25519.X25519PrivateKey.generate()
                self.pkey2 =  x25519.X25519PrivateKey.generate()
            elif self.type == 'p256':
                self.pkey1 =  ec.generate_private_key(ec.SECP256R1())
                self.pkey2 =  ec.generate_private_key(ec.SECP256R1())
            else:
                raise("Key type not supported")
            kbytes1 = self.pkey1.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            kbytes2 = self.pkey2.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            tempfile.tempdir = '/tmp'
            keyfile = tempfile.NamedTemporaryFile(prefix="microsurf_key_gen", suffix=".key").name
            with open(keyfile, 'wb') as f:
                f.write(kbytes1)
                f.write(kbytes2)
            # only append the first key
            # TODO: we should probably append both keys
            self.secrets.append((keyfile, self.pkey1)) 
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
