import argparse
import getpass
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def main():
    parser = argparse.ArgumentParser(description="Decrypt an encrypted file")
    parser.add_argument("--name", required=True, help="Key owner name")
    parser.add_argument("file", help="Encrypted file (.enc)")
    args = parser.parse_args()

    passphrase = getpass.getpass("Enter passphrase: ").encode()

    private_key_path = f"keys/private/{args.name}_private.pem"

    with open(private_key_path, "rb") as f:
        from cryptography.hazmat.backends import default_backend

        private_key = serialization.load_pem_private_key(
            f.read(),
            password=passphrase,
            backend=default_backend()
        )

    with open(args.file, "rb") as f:
        ciphertext = f.read()

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    output_file = args.file.replace(".enc", ".decrypted.txt")
    with open(output_file, "wb") as f:
        f.write(plaintext)

    print(f"Decrypted file saved as: {output_file}")

if __name__ == "__main__":
    main()
