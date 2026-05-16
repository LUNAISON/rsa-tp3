import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt(plain_text, key):
    # 1. Générer un IV aléatoire de 16 octets
    iv = os.urandom(16)
    
    # 2. Préparer le padding (PKCS7) pour atteindre un multiple de 128 bits
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    
    # 3. Configurer l'algorithme AES en mode CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 4. Chiffrer
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    
    # On retourne l'IV accolé au texte chiffré (besoin de l'IV pour déchiffrer)
    return iv + cipher_text

def decrypt(token, key):
    # 1. Extraire l'IV (les 16 premiers octets) et le corps chiffré
    iv = token[:16]
    cipher_text = token[16:]
    
    # 2. Configurer le déchiffrement
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # 3. Déchiffrer les données
    padded_data = decryptor.update(cipher_text) + decryptor.finalize()
    
    # 4. Retirer le padding
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data.decode()

# --- TEST PRATIQUE ---
if __name__ == "__main__":
    # Clé de 32 octets pour de l'AES-256
    secret_key = os.urandom(32)
    message = "Ceci est un secret pour les hackers de la séance 2"
    
    print(f"Message original : {message}")
    
    # Chiffrement
    token = encrypt(message, secret_key)
    print(f"Texte chiffré (hex) : {token.hex()}")
    
    # Déchiffrement
    clear_text = decrypt(token, secret_key)
    print(f"Message déchiffré : {clear_text}")
