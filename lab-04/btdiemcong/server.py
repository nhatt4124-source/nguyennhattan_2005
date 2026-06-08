from flask import Flask, request, jsonify, Response, render_template
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import queue
import json
import threading
import time
import sys

# Reconfigure stdout/stderr to UTF-8 to prevent charmap codec errors on Windows
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

app = Flask(__name__, static_folder='static', template_folder='templates')

# Generate RSA key pair for the server on startup
server_key = RSA.generate(2048)
server_public_pem = server_key.publickey().export_key(format='PEM').decode('utf-8')

# Thread-safe client management
clients = {}
lock = threading.Lock()

def safe_print(*args, **kwargs):
    """Safe print utility to prevent console encoding crashes on Windows"""
    try:
        print(*args, **kwargs)
    except Exception:
        pass

def broadcast_client_list():
    with lock:
        active_clients = [{"id": cid, "name": cinfo["name"]} for cid, cinfo in clients.items()]
    
    payload = {
        "event_type": "client_list",
        "data": {
            "clients": active_clients
        }
    }
    
    with lock:
        for cid, cinfo in clients.items():
            cinfo["queue"].put(payload)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/server-key', methods=['GET'])
def get_server_key():
    return jsonify({
        "public_key": server_public_pem
    })

@app.route('/api/register', methods=['POST'])
def register_client():
    data = request.json
    client_id = data.get('client_id')
    name = data.get('name')
    client_public_pem = data.get('public_key')
    
    if not client_id or not name or not client_public_pem:
        return jsonify({"error": "Missing registration data"}), 400
        
    try:
        # Import the client's public key
        client_pub_key = RSA.import_key(client_public_pem)
        
        # Generate a unique 16-byte (128-bit) AES key for the client
        aes_key = get_random_bytes(16)
        
        # Encrypt the AES key with the client's RSA public key (RSA-OAEP with SHA-256)
        cipher_rsa = PKCS1_OAEP.new(client_pub_key, hashAlgo=SHA256)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        encrypted_aes_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
        
        with lock:
            # If client already exists, clean up old queue
            clients[client_id] = {
                "name": name,
                "public_key": client_pub_key,
                "aes_key": aes_key,
                "queue": queue.Queue()
            }
            
        # Notify other clients of the new user
        broadcast_client_list()
        
        return jsonify({
            "encrypted_aes_key": encrypted_aes_b64
        })
    except Exception as e:
        safe_print(f"Error registering client {name}: {str(e)}")
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500

@app.route('/api/send', methods=['POST'])
def send_message():
    data = request.json
    client_id = data.get('client_id')
    iv_b64 = data.get('iv')
    ciphertext_b64 = data.get('ciphertext')
    
    if not client_id or not iv_b64 or not ciphertext_b64:
        return jsonify({"error": "Invalid message format"}), 400
        
    with lock:
        client = clients.get(client_id)
        
    if not client:
        return jsonify({"error": "Client not registered"}), 401
        
    try:
        # Decrypt message from sender using their unique AES key
        aes_key = client['aes_key']
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted_bytes = unpad(decrypted_padded, AES.block_size)
        message_text = decrypted_bytes.decode('utf-8')
        
        safe_print(f"[SECURE MESSAGE] Decrypted from {client['name']} ({client_id}): {message_text}")
        
        # Construct message packet
        msg_packet = {
            "sender_name": client['name'],
            "sender_id": client_id,
            "message": message_text,
            "timestamp": time.time()
        }
        
        # Broadcast to all other registered clients
        with lock:
            recipients = [(cid, cinfo) for cid, cinfo in clients.items() if cid != client_id]
            
        for rid, rinfo in recipients:
            # Encrypt message for recipient using recipient's unique AES key
            r_aes_key = rinfo['aes_key']
            r_cipher = AES.new(r_aes_key, AES.MODE_CBC)
            payload_bytes = json.dumps(msg_packet).encode('utf-8')
            padded_payload = pad(payload_bytes, AES.block_size)
            r_ciphertext = r_cipher.encrypt(padded_payload)
            r_iv = r_cipher.iv
            
            encrypted_payload = {
                "event_type": "chat_message",
                "iv": base64.b64encode(r_iv).decode('utf-8'),
                "ciphertext": base64.b64encode(r_ciphertext).decode('utf-8')
            }
            
            rinfo['queue'].put(encrypted_payload)
            
        return jsonify({"status": "delivered"})
    except Exception as e:
        safe_print(f"Error handling secure message: {str(e)}")
        return jsonify({"error": f"Decryption/Relay failed: {str(e)}"}), 500

@app.route('/api/stream')
def event_stream():
    client_id = request.args.get('client_id')
    
    with lock:
        has_client = client_id in clients
        
    if not client_id or not has_client:
        return Response("Unauthorized", status=401)
        
    def stream_generator():
        safe_print(f"[STREAM] Client connected: {client_id}")
        
        # Immediate client list sync to the newly connected user
        broadcast_client_list()
        
        with lock:
            if client_id in clients:
                q = clients[client_id]['queue']
            else:
                return
                
        try:
            while True:
                try:
                    # Timeout of 5s allows checking if connection remains active
                    packet = q.get(timeout=5)
                    
                    if packet.get("event_type") == "client_list":
                        yield f"event: client_list\ndata: {json.dumps(packet['data'])}\n\n"
                    elif packet.get("event_type") == "chat_message":
                        # Strip event_type from data payload to keep it clean
                        payload = {
                            "iv": packet["iv"],
                            "ciphertext": packet["ciphertext"]
                        }
                        yield f"event: chat_message\ndata: {json.dumps(payload)}\n\n"
                except queue.Empty:
                    # Keep-alive comment to prevent SSE timeout
                    yield ": keep-alive\n\n"
        except GeneratorExit:
            safe_print(f"[STREAM] Client connection closed (GeneratorExit): {client_id}")
        except Exception as e:
            safe_print(f"[STREAM] Client connection error: {str(e)}")
        finally:
            with lock:
                if client_id in clients:
                    name = clients[client_id]['name']
                    del clients[client_id]
                    safe_print(f"[STREAM] Cleaned up client: {name} ({client_id})")
            
            # Broadcast updated list since a client disconnected
            broadcast_client_list()
            
    return Response(stream_generator(), mimetype="text/event-stream")

if __name__ == '__main__':
    # Start the server on port 5000, listening on all interfaces
    app.run(host='0.0.0.0', port=5000, debug=True)
