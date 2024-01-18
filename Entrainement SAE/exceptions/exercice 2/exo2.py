import os

# Définir la variable filename avec le chemin du fichier à lire
filename = "exercice 2/exo2.txt" 

try:
    # Vérifier si le fichier existe
    if not os.path.exists(filename):
        raise FileNotFoundError("Le fichier spécifié n'a pas été trouvé.")
    
    # Ouvrir le fichier en mode lecture
    with open(filename, 'r') as file:
        # Parcourir chaque ligne du fichier
        for line in file:
            # Supprimer les caractères de nouvelle ligne de la ligne
            line = line.rstrip("\n\r")
            # Afficher la ligne dans la console
            print(line)
except IOError:
    # Si une erreur se produit lors de la lecture du fichier, afficher un message d'erreur
    print("Erreur: Une erreur d'entrée/sortie s'est produite lors de la manipulation du fichier.")
except Exception as e:
    # Si une autre erreur se produit, afficher le message d'erreur
    print(f"Erreur: {e}")
finally:
    # Afficher un message indiquant la fin du programme
    print("Fin du programme.")