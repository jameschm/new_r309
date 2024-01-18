def main():
    try:
        x = int(input("Entrez la valeur de x: "))
        y = int(input("Entrez la valeur de y: "))
        print(divEntier(x, y))
    except ValueError as e:
        print("Erreur:", e)

def divEntier(x: int, y: int) -> int:
    try:
        if x < 0 or y < 0:
            raise ValueError("Les nombres doivent être positifs")
        if y == 0:
            raise ValueError("La division par zéro n'est pas autorisée")
        if x < y:
            return 0
        else:
            x = x - y
            return divEntier(x, y) + 1
    except ValueError as e:
        raise e
    
if __name__ == "__main__":
    main()
