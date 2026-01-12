```Directory Structure:

crypto_cli/
├── keys/
│   ├── public/
│   └── private/
├── messages/
├── generate_keys.py
├── encrypt_file.py
└── decrypt_file.py

Usage:

python generate_keys.py --name alice
python encrypt_file.py messages/secret.txt
python decrypt_file.py --name alice messages/secret.txt.enc
