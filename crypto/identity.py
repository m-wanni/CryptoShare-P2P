import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

class Identity:
    def __init__(self, key_path):
        self.private_key = None
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
        else:
            self.private_key = Ed25519PrivateKey.generate()
            with open(key_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
        self.public_key = self.private_key.public_key()
    
    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)
    
    #Verify peers signature and message
    def verify(self, signature: bytes, message: bytes, peer_pub_bytes: bytes) -> bool:
        peer_pub_key = Ed25519PublicKey.from_public_bytes(peer_pub_bytes)
        try:
            peer_pub_key.verify(signature, message)
            return True
        except:
            return False
    
    def get_public_key_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )