"""
https://github.com/jameschm/R309/tree/1dcfe2cf30364727fdcc34d55bb0031c54fccd5a/Entrainement%20SAE/Examen


Question 1:
Pour arrêter correctement le client, le client doit envoyer un message spécial, 
comme "deco-client", au serveur pour indiquer qu'il se déconnecte volontairement. 
Ensuite, le serveur doit fermer la connexion du client et le supprimer de la liste des clients. 
Enfin, le client doit fermer sa propre connexion après avoir envoyé le message.

Question 2:
Pour gérer plusieurs clients, le serveur doit créer une nouvelle thread pour chaque client accepté, 
au lieu d'une seule pour le premier client. De cette façon, le serveur peut gérer les messages de 
plusieurs clients en même temps. De plus, le serveur doit envoyer les messages reçus d'un client à tous 
les autres clients connectés, pour que tout le monde puisse participer à la conversation.
"""


import socket
import threading
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QLabel, QWidget

class ServeurChat(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Serveur de chat")

        self.widget = QWidget()
        self.layout = QVBoxLayout()

        self.label_serveur = QLabel("Serveur de chat")
        self.entry_serveur = QLineEdit("0.0.0.0")
        self.label_port = QLabel("Port")
        self.entry_port = QLineEdit("10000")
        self.label_max_clients = QLabel("Nombre maximum de clients")
        self.entry_max_clients = QLineEdit("5")

        self.button_demarrer = QPushButton("Démarrer le serveur", clicked=self.__demarrer)
        self.button_quitter = QPushButton("Quitter", clicked=self.close)

        self.text_chat = QTextEdit()
        self.text_chat.setReadOnly(True)

        self.layout.addWidget(self.label_serveur)
        self.layout.addWidget(self.entry_serveur)
        self.layout.addWidget(self.label_port)
        self.layout.addWidget(self.entry_port)
        self.layout.addWidget(self.label_max_clients)
        self.layout.addWidget(self.entry_max_clients)
        self.layout.addWidget(self.button_demarrer)
        self.layout.addWidget(self.text_chat)
        self.layout.addWidget(self.button_quitter)

        self.widget.setLayout(self.layout)
        self.setCentralWidget(self.widget)

        self.socket_serveur = None
        self.sockets_clients = []

        self.show()

    def __demarrer(self):
        if self.socket_serveur is None:
            serveur = self.entry_serveur.text()
            port = self.entry_port.text()
            max_clients = self.entry_max_clients.text()

            try:
                port = int(port)
                max_clients = int(max_clients)
            except ValueError:
                self.text_chat.append("Le port et le nombre de clients doivent être des entiers.")
                return

            try:
                self.socket_serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket_serveur.bind((serveur, port))
                self.socket_serveur.listen(max_clients)
            except socket.error as e:
                self.text_chat.append(f"Erreur lors de la création du socket serveur : {e}")
                return

            self.button_demarrer.setText("Arrêter le serveur")

            self.thread_accepter = threading.Thread(target=self.__accepter)
            self.thread_accepter.start()

        else:
            self.socket_serveur.close()
            self.socket_serveur = None

            for socket_client in self.sockets_clients:
                socket_client.close()

            self.sockets_clients = []

            self.button_demarrer.setText("Démarrer le serveur")

    def __accepter(self):
        while self.socket_serveur is not None:
            try:
                socket_client, adresse_client = self.socket_serveur.accept()
            except socket.error as e:
                self.text_chat.append(f"Erreur lors de l'acceptation d'un client : {e}")
                continue

            self.sockets_clients.append(socket_client)

            self.text_chat.append(f"Un client s'est connecté depuis {adresse_client}")

            self.thread_recevoir = threading.Thread(target=self.__recevoir, args=(socket_client,))
            self.thread_recevoir.start()

    def __recevoir(self, socket_client):
        while socket_client in self.sockets_clients:
            try:
                message = socket_client.recv(1024).decode()
            except socket.error as e:
                self.text_chat.append(f"Erreur lors de la réception d'un message : {e}")
                continue

            if not message or message == "deco-serveur":
                socket_client.close()
                self.sockets_clients.remove(socket_client)
                self.text_chat.append("Un client s'est déconnecté.")
                break

            else:
                self.text_chat.append(f"Client : {message}")

app = QApplication([])
serveur_chat = ServeurChat()
app.exec_()