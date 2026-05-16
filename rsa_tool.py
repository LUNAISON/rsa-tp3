from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
# ==========================================
# 1. GÉNÉRATION ET SAUVEGARDE DES CLÉS
# ==========================================
def generate_keys():
    print("[*] Génération de la paire de clés RSA (2048 bits)...")
    # Génération de la clé privée
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Déduction de la clé publique
    public_key = private_key.public_key()
    # Sauvegarde de la clé privée (Format PEM)
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() # Pas de mot de passe pour le TP
        ))
    # Sauvegarde de la clé publique (Format PEM)
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("[+] Clés sauvegardées (private_key.pem et public_key.pem)")
    return private_key, public_key
# ==========================================
# 2. CHIFFREMENT (Avec clé Publique)
# ==========================================
def encrypt_rsa(message, public_key):
    # On utilise OAEP, le standard de padding sécurisé pour RSA
    cipher_text = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher_text
# ==========================================
# 3. DÉCHIFFREMENT (Avec clé Privée)
# ==========================================
def decrypt_rsa(cipher_text, private_key):
    plain_text = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plain_text.decode()
# --- TEST PRATIQUE ---
if __name__ == "__main__":
    # 1. Création des clés
    priv_key, pub_key = generate_keys()
    
    message = "Code secret de la banque UEMOA : 4598"
    print(f"\nMessage clair : {message}")
    
    # 2. Chiffrement
    token = encrypt_rsa(message, pub_key)
    print(f"\nTexte chiffré (hex) : {token.hex()[:50]}... (tronqué)")
    
    # 3. Déchiffrement
    clear_text = decrypt_rsa(token, priv_key)
    print(f"\nMessage déchiffré : {clear_text}")
