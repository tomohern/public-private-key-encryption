from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import getpass

# Prompt for an alphanumeric passphrase
passphrase = getpass.getpass("Enter an alphanumeric passphrase: ").encode()

# Generate RSA private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

# Serialize and encrypt private key
with open("private_key.pem", "wb") as priv_file:
    priv_file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
        )
    )

# Serialize public key
with open("public_key.pem", "wb") as pub_file:
    pub_file.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("Key pair generated:")
print("- public_key.pem")
print("- private_key.pem (encrypted)")
