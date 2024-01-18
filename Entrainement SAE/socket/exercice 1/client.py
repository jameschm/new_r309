# client.py
import socket

def client():
    hôte = '10.171.251.102'
    port = 12345

    socket_client = socket.socket()
    socket_client.connect((hôte, port))

    message = input("Entrez votre message : ")

    while message.lower().strip() != 'bye':
        socket_client.send(message.encode())
        if message.lower().strip() == 'arret':
            break
        données = socket_client.recv(1024).decode()
        print("Reçu du serveur : " + données)
        message = input("Entrez votre message : ")

    socket_client.close()

if __name__ == "__main__":
    client()