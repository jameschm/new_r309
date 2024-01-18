# client.py
import socket
import threading

class ThreadReception(threading.Thread):
    def __init__(self, conn):
        threading.Thread.__init__(self)
        self.conn = conn

    def run(self):
        while True:
            try:
                data = self.conn.recv(1024).decode()
                if not data or data.lower().strip() == 'arret':
                    self.conn.close()
                    print("Connexion avec le serveur fermée")
                    print("Le serveur a été arrêté.")
                    break
                print(data)
            except:
                break

def start_client():
    host = '10.171.251.102'  # remplacez par l'adresse IP du serveur
    port = 12345  # remplacez par le port du serveur

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    print("Connecté au serveur")

    thread_reception = ThreadReception(client_socket)
    thread_reception.start()

    while True:
        msg = input()
        if msg.lower().strip() == 'arret':
            client_socket.send(msg.encode())
            break
        client_socket.send(msg.encode())

    client_socket.close()

if __name__ == "__main__":
    start_client()