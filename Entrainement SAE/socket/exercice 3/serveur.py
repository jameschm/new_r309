# server.py
import socket
import threading
import queue
import json

stop_event = threading.Event()  # Événement pour signaler l'arrêt du serveur

def handle_client_receive(conn, address, clients, message_queue, users):
    while not stop_event.is_set():  # Vérifie si l'événement d'arrêt est activé
        try:
            data = conn.recv(1024).decode()
            if not data or data.lower().strip() == 'bye':
                conn.close()
                print(f"Connexion avec {address} fermée")
                break
            if data.lower().strip() == 'arret':
                print(f"Le client à {address} a demandé l'arrêt du serveur.")
                message_queue.put('arret')  # Diffuse 'arret' à tous les clients
                conn.close()               
                break
            # Ajoute le surnom de l'expéditeur au message
            nickname = users.get(str(address), "Inconnu") # Convertit le tuple d'adresse en chaîne de caractères
            message = f"{nickname}: {data}"
            
            # Diffuse le message à tous les clients
            for client in clients:
                if client != conn:  # N'envoie pas le message à l'expéditeur
                    client.send(message.encode())
        except ConnectionResetError:
            print(f"Le client à {address} s'est déconnecté")
            break

def handle_client_send(conn, address, clients, message_queue):
    while not stop_event.is_set() and clients:  # Vérifie si l'événement d'arrêt est activé ou s'il ne reste plus de clients
        try:
            if stop_event.is_set():
                break
            if conn.fileno() == -1:
                break  # Arrête si la socket est fermée

            if not message_queue.empty():
                message = message_queue.get()
                conn.send(message.encode())

                if message.lower().strip() == 'arret':
                    conn.close()
                    socket.close()
                    break

        except ConnectionResetError:
            print(f"Le client à {address} s'est déconnecté")
            break

def server():
    global stop_event  # Accède à la variable globale
    host = '0.0.0.0'
    port = 12345

    server_socket = socket.socket()
    server_socket.bind((host, port))

    server_socket.listen(5)
    print("Le serveur écoute sur le port", port)

    clients = []
    message_queue = queue.Queue()
    users = {}  # Un dictionnaire pour stocker les surnoms des clients par leur adresse

    try:
        input_thread_instance = threading.Thread(args=(message_queue,))
        input_thread_instance.start()

        while not stop_event.is_set():  # Vérifie si l'événement d'arrêt est activé
            conn, address = server_socket.accept()
            if stop_event.is_set():
                conn.close()
                break  # Arrête d'accepter de nouvelles connexions si le serveur s'arrête
            print("Connexion depuis", address)
            clients.append(conn)

            # Demande au client son surnom
            conn.send("Bienvenue dans le chat en diffusion. Veuillez entrer votre surnom : ".encode())
            nickname = conn.recv(1024).decode()
            print(f"L'utilisateur à {address} a choisi le surnom {nickname}")
            # Enregistre le surnom dans le fichier json
            users[str(address)] = nickname # Convertit le tuple d'adresse en chaîne de caractères
            with open("users.json", "w") as f:
                json.dump(users, f)

            receive_thread = threading.Thread(target=handle_client_receive, args=(conn, address, clients, message_queue, users))
            receive_thread.start()

            send_thread = threading.Thread(target=handle_client_send, args=(conn, address, clients, message_queue))
            send_thread.start()

        print("Le serveur s'arrête.")
        for conn in clients:
            conn.close()

        server_socket.close()

    except KeyboardInterrupt:
        pass  # Permet à KeyboardInterrupt de se propager en dehors de la boucle

    stop_event.set()  # Définit la variable globale pour signaler l'arrêt du serveur

    input_thread_instance.join()

    for conn in clients:
        conn.close()

    server_socket.close()


if __name__ == "__main__":
    server()

