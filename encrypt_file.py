import argparse
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from pathlib import Path

def list_public_keys():
    pub_dir = Path("keys/public")
    return list(pub_dir.glob("*_public.pem"))

def main():
    parser = argparse.ArgumentParser(description="Encrypt a text file")
    parser.add_argument("file", help="Path to .txt file to encrypt")
    args = parser.parse_args()

    public_keys = list_public_keys()

    if not public_keys:
        print("No public keys found.")
        return

    print("Available public keys:")
    for i, key in enumerate(public_keys):
        print(f"[{i}] {key.name}")

    choice = int(input("Select public key number: "))
    pub_key_path = public_keys[choice]

    with open(pub_key_path, "rb") as f:
        from cryptography.hazmat.backends import default_backend

        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
            with open(args.file, "rb") as f:
                plaintext = f.read()

    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    output_file = args.file + ".enc"
    with open(output_file, "wb") as f:
        f.write(ciphertext)

    print(f"Encrypted file saved as: {output_file}")

if __name__ == "__main__":
    main()
