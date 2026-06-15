from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import sys

# Reconfigure stdout/stderr to UTF-8 to prevent charmap codec errors on Windows
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass


def generate_client_key_pair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key, server_public_key):
    shared_key = private_key.exchange(server_public_key)
    return shared_key

def main():
    # Load server's public key
    with open('server_public_key.pem', 'rb') as f:
        server_public_key = serialization.load_pem_public_key(f.read())

    parameters = server_public_key.parameters()
    private_key, public_key = generate_client_key_pair(parameters)

    shared_secret = derive_shared_secret(private_key, server_public_key)
    print(f"Shared Secret: {shared_secret.hex()}")

if __name__ == '__main__':
    main()
