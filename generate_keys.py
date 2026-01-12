import argparse
import getpass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Generate RSA key pair")
    parser.add_argument("--name", required=True, help="Unique name for the key owner")
    args = parser.parse_args()

    passphrase = getpass.getpass("Enter alphanumeric passphrase: ").encode()

    # Generate key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    # Create directories
    Path("keys/public").mkdir(parents=True, exist_ok=True)
    Path("keys/private").mkdir(parents=True, exist_ok=True)

    # Save public key
    pub_path = f"keys/public/{args.name}_public.pem"
    with open(pub_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    # Save encrypted private key
    priv_path = f"keys/private/{args.name}_private.pem"
    with open(priv_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
            )
        )

    print(f"Keys generated:")
    print(f" Public:  {pub_path}")
    print(f" Private: {priv_path} (encrypted)")

if __name__ == "__main__":
    main()
