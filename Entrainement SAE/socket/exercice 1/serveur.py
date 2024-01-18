# server.py
import socket

def serveur():
    hote = '0.0.0.0'
    port = 12345

    socket_serveur = socket.socket()
    socket_serveur.bind((hote, port))

    socket_serveur.listen(1)
    print("Le serveur écoute sur le port", port)

    en_cours = True
    while en_cours:  # Cette boucle permet au serveur de continuer à accepter de nouvelles connexions
        conn, adresse = socket_serveur.accept()
        print("Connexion depuis", adresse)

        while True:
            donnees = conn.recv(1024).decode()
            if not donnees or donnees.lower() == 'bye':
                break
            if donnees.lower() == 'arret':
                en_cours = False
                break
            print("Reçu du client : " + donnees)
            donnees = input("Entrez un message à envoyer au client: ")
            conn.send(donnees.encode())

        print("Client déconnecté")
        conn.close()

if __name__ == "__main__":
    serveur()