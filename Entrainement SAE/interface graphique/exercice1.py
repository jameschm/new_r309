from PySide6.QtWidgets import QApplication, QWidget, QLabel, QPushButton, QVBoxLayout, QLineEdit

class MaFenetre(QWidget):
    def __init__(self):
        super().__init__()

        # Définir le titre de la fenêtre
        self.setWindowTitle("Ma première fenêtre")

        # Créer un widget QLabel pour afficher le message
        self.label = QLabel("")

        # Créer un widget QLineEdit pour la saisie du nom
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Entrez votre nom")

        # Créer un widget QPushButton pour déclencher le message
        self.button_ok = QPushButton("OK")
        self.button_ok.clicked.connect(self.afficher_message)

        # Créer un widget QPushButton pour quitter l'application
        self.button_quit = QPushButton("Quitter")
        self.button_quit.clicked.connect(self.close)

        # Créer un QVBoxLayout pour organiser les widgets verticalement
        layout = QVBoxLayout()
        layout.addWidget(self.name_input)
        layout.addWidget(self.button_ok)
        layout.addWidget(self.label)
        layout.addWidget(self.button_quit)

        self.setLayout(layout)

    def afficher_message(self):
        # Obtenir le nom à partir du widget QLineEdit
        name = self.name_input.text()

        # Afficher le message personnalisé
        self.label.setText(f"Bonjour {name}!")

if __name__ == "__main__":
    app = QApplication([])
    fenetre = MaFenetre()
    fenetre.resize(300, 200)
    fenetre.show()
    app.exec()