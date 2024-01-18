# client.py
import socket
import threading

def recevoir_message(client_socket):
    while True:
        try:
            data = client_socket.recv(1024).decode()
            print("Reçu du serveur : " + data)
        except:
            print("Connexion perdue")
            break

def client():
    hôte = '10.171.251.102'
    port = 12345

    client_socket = socket.socket()
    client_socket.connect((hôte, port))

    thread_reception = threading.Thread(target=recevoir_message, args=(client_socket,))
    thread_reception.start()

    while True:
        message = input("Entrez votre message : ")
        client_socket.send(message.encode())
        if message.lower().strip() == 'bye':
            break
        if message.lower().strip() == 'arret':
            client_socket.close()
            break

if __name__ == "__main__":
    client()