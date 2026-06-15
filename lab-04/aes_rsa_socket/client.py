from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import socket
import threading
import sys

# Reconfigure stdout/stderr to UTF-8 to prevent charmap codec errors on Windows
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

# Initialize client socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

# Generate RSA key pair
client_key = RSA.generate(2048)

# Receive server's public key
server_public_key = RSA.import_key(client_socket.recv(2048))

# Send client's public key to the server
client_socket.send(client_key.publickey().export_key(format='PEM'))

# Receive encrypted AES key from the server
encrypted_aes_key = client_socket.recv(2048)

# Decrypt the AES key using client's private key
cipher_rsa = PKCS1_OAEP.new(client_key)
aes_key = cipher_rsa.decrypt(encrypted_aes_key)

# Function to encrypt message
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

# Function to decrypt message
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode()

# Function to receive messages from server
def receive_messages():
    try:
        while True:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                print("\nServer closed the connection.")
                break
            try:
                decrypted_message = decrypt_message(aes_key, encrypted_message)
                print(f"\nReceived: {decrypted_message}")
                print("Enter message ('exit' to quit): ", end="", flush=True)
            except Exception as e:
                print(f"\nError decrypting message: {e}")
    except (ConnectionResetError, ConnectionAbortedError):
        print("\nConnection to server lost.")
    except Exception as e:
        print(f"\nError receiving message: {e}")

# Start the receiving thread
receive_thread = threading.Thread(target=receive_messages, daemon=True)
receive_thread.start()

# Send messages from the client
try:
    while True:
        message = input("Enter message ('exit' to quit): ")
        encrypted_message = encrypt_message(aes_key, message)
        client_socket.send(encrypted_message)
        if message == 'exit':
            break
except (KeyboardInterrupt, EOFError):
    pass
except Exception as e:
    print(f"Error sending message: {e}")
finally:
    # Close the connection when done
    client_socket.close()

