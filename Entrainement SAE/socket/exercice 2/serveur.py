# server.py
import socket
import threading

stop_server = False  # Global variable to signal when the server is stopping

def handle_client_receive(conn, address, clients):
    while True:
        try:
            data = conn.recv(1024).decode()
            if not data or data.lower().strip() == 'bye':
                break
            if data.lower().strip() == 'arret':
                print(f"Client at {address} has requested to stop the server.")
                conn.send("Server is stopping. Goodbye!".encode())
                break
            print(f"Received from {address}: {data}")
        except ConnectionResetError:
            print(f"Client at {address} disconnected")
            break

    conn.close()
    print(f"Connection with {address} closed")


def handle_client_send(conn, address, clients):
    global stop_server  # Access the global variable
    while True:
        if stop_server or not clients:
            break  # Stop the loop if the server is stopping or no clients left
        try:
            message = input("Enter message to send to client: ")
            conn.send(message.encode())
            if message.lower().strip() == 'arret':
                print("Server is stopping. Goodbye!")
                break
        except ConnectionResetError:
            print(f"Client at {address} disconnected")
            break

def server():
    host = '0.0.0.0'
    port = 12345

    server_socket = socket.socket()
    server_socket.bind((host, port))

    server_socket.listen(5)
    print("Server is listening on port", port)

    clients = []

    try:
        while True:
            conn, address = server_socket.accept()
            print("Connection from", address)
            clients.append(conn)

            receive_thread = threading.Thread(target=handle_client_receive, args=(conn, address, clients))
            receive_thread.start()

            send_thread = threading.Thread(target=handle_client_send, args=(conn, address, clients))
            send_thread.start()

    except KeyboardInterrupt:
        global stop_server
        print("Server is stopping.")
        stop_server = True  # Set the global variable to signal the server to stop

        for conn in clients:
            conn.close()

        server_socket.close()

if __name__ == "__main__":
    server()