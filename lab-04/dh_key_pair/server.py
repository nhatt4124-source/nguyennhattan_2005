from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import sys

# Reconfigure stdout/stderr to UTF-8 to prevent charmap codec errors on Windows
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass


def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    return parameters

def generate_server_key_pair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def main():
    parameters = generate_dh_parameters()
    private_key, public_key = generate_server_key_pair(parameters)

    with open('server_public_key.pem', 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

if __name__ == '__main__':
    main()
