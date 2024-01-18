import csv

class Article:
    TAX = 0.2  # Taxe appliquée sur le prix de l'article

    def __init__(self, nom, codebar, prix_hors_tax):
        """
        Constructeur de la classe Article.
        :param nom: Nom de l'article
        :param codebar: Code barre de l'article
        :param prix_hors_tax: Prix hors taxe de l'article
        """
        if prix_hors_tax <= 0:
            raise ValueError("Le prix doit être supérieur à 0")
        self._nom = nom
        self._codebar = codebar
        self._prix_hors_tax = prix_hors_tax

    @property
    def nom(self):
        """Retourne le nom de l'article."""
        return self._nom

    @property
    def codebar(self):
        """Retourne le code barre de l'article."""
        return self._codebar

    @property
    def prix_hors_tax(self):
        """Retourne le prix hors taxe de l'article."""
        return self._prix_hors_tax

    @prix_hors_tax.setter
    def prix_hors_tax(self, nouveau_prix):
        """Définit un nouveau prix hors taxe pour l'article."""
        if nouveau_prix <= 0:
            raise ValueError("Le prix doit être supérieur à 0")
        self._prix_hors_tax = nouveau_prix

    def prix_avec_tax(self):
        """Calcule et retourne le prix de l'article avec taxe."""
        return self._prix_hors_tax * (1 + self.TAX)

    def __str__(self):
        """Retourne une représentation sous forme de chaîne de l'article."""
        return f"Article(nom={self._nom}, codebar={self._codebar}, prix_hors_tax={self._prix_hors_tax})"


class Stock:
    def __init__(self):
        """Constructeur de la classe Stock."""
        self.articles = {}

    def taille(self):
        """Retourne le nombre d'articles dans le stock."""
        return len(self.articles)

    def ajout(self, article):
        """Ajoute un article au stock."""
        if article.codebar in self.articles:
            raise ValueError("Un article avec ce codebar existe déjà")
        self.articles[article.codebar] = article

    def recherche_codebar(self, codebar):
        """Recherche un article dans le stock par son code barre."""
        if codebar not in self.articles:
            raise ValueError("Cet article n'est pas dans le stock")
        return self.articles[codebar]

    def recherche_nom(self, nom):
        """Recherche un article dans le stock par son nom."""
        for article in self.articles.values():
            if article.nom == nom:
                return article
        raise ValueError("Cet article n'est pas dans le stock")

    def supprime_codebar(self, codebar):
        """Supprime un article du stock par son code barre."""
        if codebar not in self.articles:
            raise ValueError("Cet article n'est pas dans le stock")
        del self.articles[codebar]

    def supprime_nom(self, nom):
        """Supprime un article du stock par son nom."""
        for codebar, article in list(self.articles.items()):
            if article.nom == nom:
                del self.articles[codebar]
                return
        raise ValueError("Cet article n'est pas dans le stock")

    def charger_csv(self, filename):
        """
        Charge les articles depuis un fichier CSV.
        :param filename: Nom du fichier CSV
        """
        try:
            with open(filename, 'r') as file:
                reader = csv.DictReader(file, delimiter=';')
                for row in reader:
                    article = Article(row['nom'], row['codebar'], float(row['prix_hors_tax']))
                    self.ajout(article)
        except Exception as e:
            print(f"Erreur lors de la lecture du fichier CSV: {e}")

    def sauvegarde_csv(self, filename):
        """
        Sauvegarde les articles dans un fichier CSV.
        :param filename: Nom du fichier CSV
        """
        try:
            with open(filename, 'w') as file:
                fieldnames = ['nom', 'codebar', 'prix_hors_tax']
                writer = csv.DictWriter(file, fieldnames=fieldnames, delimiter=';')
                writer.writeheader()
                for article in self.articles.values():
                    writer.writerow({'nom': article.nom, 'codebar': article.codebar, 'prix_hors_tax': article.prix_hors_tax})
        except Exception as e:
            print(f"Erreur lors de l'écriture du fichier CSV: {e}")

# Exemple d'utilisation des classes Article et Stock
article1 = Article("laptop", "123456789", 1000)

print(article1)  # Affiche les détails de l'article

stock = Stock()  # Crée un nouveau stock

stock.ajout(article1)  # Ajoute l'article au stock

print(stock.taille())  # Affiche la taille du stock

found_article = stock.recherche_codebar("123456789")  # Recherche un article par son code barre

print(found_article)  # Affiche les détails de l'article trouvé

stock.sauvegarde_csv("stock.csv")  # Sauvegarde le stock dans un fichier CSV

stock.articles.clear()  # Vide le stock

stock.charger_csv("stock.csv")  # Charge le stock depuis un fichier CSV

print(f"Taille du stock: {stock.taille()}")  # Affiche la taille du stock