from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
import socket, json, os
import secrets

PARAMETRES_DH = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

def hash(mdp):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(mdp.encode())
    return digest.finalize()

def oprf(mdp, nom_utilisateur):
    mdp_hashe = hash(mdp)
    r = secrets.randbits(128)  # Utiliser secrets.randbits() pour générer un nombre aléatoire plus rapidement
    C = pow(int.from_bytes(mdp_hashe, byteorder='big'), r, PARAMETRES_DH.parameter_numbers().p)  # Utiliser pow() pour effectuer l'exponentiation
    print('salut')
    envoyer(json.dumps(["OPRF", nom_utilisateur, C]))
    print("Envoi des données OPRF...")
    R = attendre()
    print("Réception des données OPRF...")
    r_inverse = pow(r, -1, PARAMETRES_DH.parameter_numbers().q)
    K = R ** r_inverse
    print("OPRF terminé avec succès.")
    return K
def deriver_cle(cle):
    sel = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sel,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(str(cle).encode())

def attendre():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(('localhost', 8080))
        print("Connexion établie avec succès.")
        reponse = sock.recv(4096)
        print("Données reçues :", reponse.decode())
    return json.loads(reponse.decode())

def envoyer(donnees):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect(('localhost', 8080))
            print("Connexion établie avec succès.")
            print("Envoi des données :", donnees)
            sock.sendall(json.dumps(donnees).encode())
            print("Données envoyées avec succès.")
        except Exception as e:
            print("Erreur lors de l'envoi des données :", e)


def register(nom_utilisateur, mdp):
    print("Début de l'enregistrement...")
    cle = oprf(mdp, nom_utilisateur)
    print("Clé obtenue :", cle)
    cle_derivee = deriver_cle(cle)
    print("Clé dérivée :", cle_derivee)
    cle_privee = PARAMETRES_DH.generate_private_key()
    print("Clé privée générée avec succès.")
    cle_publique = cle_privee.public_key()
    cle_publique_serialisee = cle_publique.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("Clé publique générée avec succès.")
    enveloppe = encrypt(cle_derivee, cle_privee.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
    print("Enveloppe créée avec succès.")
    envoyer(json.dumps(["register", nom_utilisateur, {"cle_publique": cle_publique_serialisee, "enveloppe": enveloppe}]))
    print("Enregistrement terminé avec succès.")

def encrypt(cle, donnees):
    """Chiffre les données avec la clé fournie en utilisant AES en mode CTR."""
    chiffreur = Cipher(algorithms.AES(cle[:16]), modes.CTR(os.urandom(16)), backend=default_backend()).encryptor()
    return chiffreur.update(donnees) + chiffreur.finalize()

def dencrypt(cle, enveloppe):
    """Déchiffre l'enveloppe avec la clé fournie en utilisant AES en mode CTR."""
    iv, donnees_chiffrees = enveloppe[:16], enveloppe[16:]
    dechiffreur = Cipher(algorithms.AES(cle[:16]), modes.CTR(iv), backend=default_backend()).decryptor()
    return dechiffreur.update(donnees_chiffrees) + dechiffreur.finalize()

def login(nom_utilisateur, mdp):
    print("Début de la connexion...")
    cle = oprf(mdp, nom_utilisateur)
    print("Clé obtenue :", cle)
    cle_derivee = deriver_cle(cle)
    print("Clé dérivée :", cle_derivee)
    envoyer(json.dumps(["login", nom_utilisateur]))
    print("Demande de connexion envoyée...")
    reponse = attendre()
    print("Réponse reçue :", reponse)
    enveloppe = reponse["enveloppe"]
    donnees_cle_privee = dencrypt(cle_derivee, enveloppe)
    cle_privee = serialization.load_pem_private_key(
        donnees_cle_privee, 
        password=None, 
        backend=default_backend()
    )
    print("Connexion terminée avec succès.")

def main():
    print("Début du programme.")
    nom_utilisateur = 'elies'
    mdp = 'abc'
    print('ok')
    cle = oprf(mdp, nom_utilisateur)
    clef = deriver_cle(cle)
    choix = input("register ? login ?")
    if choix.lower() == "register":
        register(nom_utilisateur, mdp)
    elif choix.lower() == "login":
        login(nom_utilisateur, mdp)
    print("Fin du programme.")

if __name__ == "__main__":
    main()
