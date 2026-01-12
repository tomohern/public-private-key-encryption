import argparse
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def list_public_keys():
    """
    Return a list of available public key files.
    """
    pub_dir = Path("keys/public")
    return list(pub_dir.glob("*_public.pem"))


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt a text file using a selected public key"
    )
    parser.add_argument(
        "file",
        help="Path to the .txt file to encrypt"
    )
    args = parser.parse_args()

    # List available public keys
    public_keys = list_public_keys()

    if not public_keys:
        print("No public keys found in keys/public/")
        return

    print("Available public keys:")
    for index, key_path in enumerate(public_keys):
        print(f"[{index}] {key_path.name}")

    # Prompt user to select a key
    try:
        choice = int(input("Select public key number: "))
        pub_key_path = public_keys[choice]
    except (ValueError, IndexError):
        print("Invalid selection.")
        return

    # Load public key
    with open(pub_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Read plaintext file
    plaintext_path = Path(args.file)
    if not plaintext_path.exists():
        print(f"File not found: {plaintext_path}")
        return

    with open(plaintext_path, "rb") as f:
        plaintext = f.read()

    # Encrypt the file contents
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write encrypted output
    output_path = plaintext_path.with_suffix(plaintext_path.suffix + ".enc")
    with open(output_path, "wb") as f:
        f.write(ciphertext)

    print(f"Encrypted file saved as: {output_path}")


if __name__ == "__main__":
    main()
