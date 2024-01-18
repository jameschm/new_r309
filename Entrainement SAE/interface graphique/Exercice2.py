from PySide6.QtWidgets import QApplication, QMainWindow, QLabel, QComboBox, QLineEdit, QPushButton, QMessageBox
from PySide6.QtCore import Qt

class MainWindow(QMainWindow):
    """
    Classe représentant la fenêtre principale de l'application de conversion de température.

    Cette fenêtre contient un label pour la température, une liste déroulante pour choisir l'unité de température,
    un champ d'édition pour entrer la température, un label pour l'unité de température, un bouton pour convertir
    la température, un bouton pour afficher l'aide et un style inspiré de Google.

    Les signaux suivants sont connectés aux slots correspondants :
    - currentTextChanged de la liste déroulante unit_combo à la méthode update_unit_label
    - clicked du bouton convert_button à la méthode convert_temperature
    - clicked du bouton help_button à la méthode show_help
    """
    def __init__(self):
        super().__init__()

        # Définir les propriétés de la fenêtre
        self.setWindowTitle("Convertisseur de température")
        self.setGeometry(100, 100, 400, 200)

        # Créer les widgets
        self.temp_label = QLabel("Température:", self)
        self.temp_label.move(20, 20)

        self.unit_combo = QComboBox(self)
        self.unit_combo.addItems(["Celsius", "Kelvin"])
        self.unit_combo.move(20, 50)

        self.temp_edit = QLineEdit(self)
        self.temp_edit.move(120, 50)

        self.unit_label = QLabel("Celsius", self)
        self.unit_label.move(250, 50)

        self.convert_button = QPushButton("Convertir", self)
        self.convert_button.move(20, 100)

        self.help_button = QPushButton("?", self)
        self.help_button.move(120, 100)

        # Connecter les signaux aux slots
        self.unit_combo.currentTextChanged.connect(self.update_unit_label)
        self.convert_button.clicked.connect(self.convert_temperature)
        self.help_button.clicked.connect(self.show_help)

        # Appliquer les styles
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f2f2f2;
            }

            QLabel {
                font-size: 16px;
                font-weight: bold;
            }

            QComboBox {
                font-size: 14px;
                padding: 5px;
                border: 2px solid #ccc;
                border-radius: 5px;
            }

            QLineEdit {
                font-size: 14px;
                padding: 5px;
                border: 2px solid #ccc;
                border-radius: 5px;
            }

            QPushButton {
                font-size: 14px;
                padding: 5px;
                border: 2px solid #ccc;
                border-radius: 5px;
                background-color: #fff;
            }

            QPushButton:hover {
                background-color: #ccc;
            }
        """)

        # Appliquer les styles inspirés de Google
        self.setStyleSheet(self.styleSheet() + """
            QMainWindow {
                background-color: #fff;
            }

            QLabel {
                color: #3c4043;
            }

            QComboBox {
                color: #3c4043;
                border: 1px solid #dadce0;
                border-radius: 8px;
                padding: 8px;
                background-color: #fff;
                selection-background-color: #4285f4;
                selection-color: #fff;
            }

            QLineEdit {
                color: #3c4043;
                border: 1px solid #dadce0;
                border-radius: 8px;
                padding: 8px;
                background-color: #fff;
                selection-background-color: #4285f4;
                selection-color: #fff;
            }

            QPushButton {
                color: #fff;
                border: none;
                border-radius: 8px;
                padding: 8px;
                background-color: #4285f4;
            }

            QPushButton:hover {
                background-color: #3c4043;
            }
        """)

    def update_unit_label(self, text):
        """
        Met à jour le label d'unité de température en fonction de la liste déroulante unit_combo.

        :param text: Le texte sélectionné dans la liste déroulante.
        """
        if text == "Celsius":
            self.unit_label.setText("Celsius")
        else:
            self.unit_label.setText("Kelvin")

    def convert_temperature(self):
        """
        Convertit la température en fonction de l'unité sélectionnée dans la liste déroulante unit_combo
        et affiche le résultat dans le champ d'édition temp_edit.

        Si la température est invalide ou inférieure au zéro absolu, une boîte de dialogue d'erreur est affichée.
        """
        try:
            temp = float(self.temp_edit.text())
        except ValueError:
            QMessageBox.warning(self, "Erreur", "Température invalide")
            return

        if self.unit_combo.currentText() == "Celsius":
            if temp < -273.15:
                QMessageBox.warning(self, "Erreur", "La température est inférieure au zéro absolu")
                return
            result = temp + 273.15
            self.unit_label.setText("Kelvin")
        else:
            if temp < 0:
                QMessageBox.warning(self, "Erreur", "La température est inférieure au zéro absolu")
                return
            result = round(temp - 273.15, 2)
            self.unit_label.setText("Celsius")

        self.temp_edit.setText(str(result))

    def show_help(self):
        """
        Affiche une boîte de dialogue d'aide avec une brève description de l'application.
        """
        QMessageBox.information(self, "Aide", "Convertit une température en degrés Celsius en degrés Kelvin et vice-versa")

if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()
    window.resize(350, 200)
    window.show()
    app.exec()

