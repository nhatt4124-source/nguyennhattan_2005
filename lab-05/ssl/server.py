import socket
import ssl
import threading

# Thông tin server
server_address = ('localhost', 12345)

# Danh sách các client đã kết nối
clients = []

def handle_client(client_socket):
    # Thêm client vào danh sách
    clients.append(client_socket)

    try:
        client_name = client_socket.getpeername()
    except:
        client_name = "Unknown"

    print("Đã kết nối với:", client_name)

    try:
        # Nhận và gửi dữ liệu
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            print("Nhận:", data.decode('utf-8'))

            # Gửi dữ liệu đến tất cả các client khác
            for client in list(clients):
                if client != client_socket:
                    try:
                        client.send(data)
                    except:
                        if client in clients:
                            clients.remove(client)
    except:
        if client_socket in clients:
            clients.remove(client_socket)
    finally:
        print("Đã ngắt kết nối:", client_name)
        if client_socket in clients:
            clients.remove(client_socket)
        client_socket.close()

# Tạo socket server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(server_address)
server_socket.listen(5)

print("Server đang chờ kết nối...")

# Lắng nghe các kết nối
while True:
    client_socket, client_address = server_socket.accept()

    # Tạo SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain(certfile="./certificates/server-cert.crt", keyfile="./certificates/server-key.key")

    # Thiết lập kết nối SSL
    ssl_socket = context.wrap_socket(client_socket, server_side=True)

    # Bắt đầu một luồng xử lý cho mỗi client
    client_thread = threading.Thread(target=handle_client, args=(ssl_socket,))
    client_thread.start()
