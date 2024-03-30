import socket
import json
import os

fichier = "users.txt"

def up():
    fichier_local = "users.txt"
    if not os.path.exists(fichier_local):
        with open(fichier_local, "w") as f:
            f.write("")

def save(nom_utilisateur, cle_publique, enveloppe, sel):
    with open(fichier, "a") as f:
        f.write(f"{nom_utilisateur} {cle_publique} {enveloppe} {sel}\n")

def search(nom_utilisateur):
    with open(fichier, "r") as f:
        for ligne in f:
            donnees = ligne.split()
            if donnees[0] == nom_utilisateur:
                return {
                    "nom_utilisateur": donnees[0],
                    "cle_publique": donnees[1],
                    "enveloppe": donnees[2],
                    "sel": donnees[3]
                }
    return None

def wait():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('localhost', 8080))
        sock.listen(1)
        conn, _ = sock.accept()
        with conn:
            donnees = conn.recv(4096)
            if donnees:
                try:
                    type_demande, nom_utilisateur, contenu = json.loads(donnees.decode())
                    if type_demande == "OPRF":
                        C = contenu
                        donnees_utilisateur = search(nom_utilisateur)
                        s = donnees_utilisateur["sel"]
                        R = C ** s
                        conn.sendall(json.dumps(R).encode())
                    elif type_demande == "register":
                        save(nom_utilisateur, contenu["cle_publique"], contenu["enveloppe"], os.urandom(16))
                    elif type_demande == "login":
                        donnees_utilisateur = search(nom_utilisateur)
                        conn.sendall(json.dumps({"enveloppe": donnees_utilisateur["enveloppe"]}).encode())
                    else:
                        print("Type de demande non reconnu.")
                except ValueError as e:
                    print("Erreur lors du décodage JSON :", e)
            else:
                print("Aucune donnée reçue.")


def main():
    up()
    print('ok')
    while True:
        wait()

if __name__ == "__main__":
    main()
