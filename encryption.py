import os
import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# === KEY DERIVATION ===
def derive_key(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """
    Derives a cryptographic key from the password and salt using PBKDF2 (Password-Based Key Derivation Function 2).
    
    Parameters:
    - password: The user's password.
    - salt: A random byte string used to prevent rainbow table attacks.
    - iterations: The number of iterations for PBKDF2. More iterations = stronger security but slower.
    
    Returns:
    - Derived key (bytes) for AES encryption.
    """
    # Create a PBKDF2HMAC object that will apply the PBKDF2 key derivation function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),   # Using SHA256 as the hash function
        length=32,  # Output key length (32 bytes = 256 bits, for AES-256 encryption)
        salt=salt,   # Salt value used in key derivation
        iterations=iterations,   # The number of iterations, higher is more secure but slower
        backend=default_backend()  # Default cryptographic backend
    )
    
    # Derive the key by applying the PBKDF2HMAC function
    return kdf.derive(password.encode())  # Encoding password into bytes for key derivation

# === ENCRYPTION ===
def encrypt(plaintext: str, password: str) -> str:
    """
    Encrypts the provided plaintext using AES-GCM encryption mode and a user password.
    
    Parameters:
    - plaintext: The text to be encrypted.
    - password: The password used to derive the AES encryption key.
    
    Returns:
    - A JSON string containing the salt, IV (Initialization Vector), and ciphertext (base64 encoded).
    """
    # Generate a random salt (16 bytes), different for each encryption to ensure uniqueness
    salt = os.urandom(16)
    
    # Derive the key using the password and salt
    key = derive_key(password, salt)
    
    # AES-GCM requires a nonce (IV). Use 12 bytes as per the standard for AES-GCM.
    iv = os.urandom(12)
    
    # AESGCM is the authenticated encryption mode that provides both encryption and integrity (authenticity)
    aesgcm = AESGCM(key)
    
    # Encrypt the plaintext. The 'None' argument means no associated data is provided for authentication.
    ciphertext = aesgcm.encrypt(iv, plaintext.encode(), None)
    
    # Prepare the encrypted data for storage or transmission as JSON
    encrypted_data = {
        "salt": base64.b64encode(salt).decode(),  # Base64 encode the salt for easier storage
        "iv": base64.b64encode(iv).decode(),      # Base64 encode the IV for easier storage
        "ciphertext": base64.b64encode(ciphertext).decode()  # Base64 encode the ciphertext
    }
    
    # Return the encrypted data as a JSON string
    return json.dumps(encrypted_data)

# === DECRYPTION ===
def decrypt(encrypted_json: str, password: str) -> str:
    """
    Decrypts an encrypted message using the AES key derived from the password and the stored salt.
    
    Parameters:
    - encrypted_json: The JSON string containing the salt, IV, and ciphertext.
    - password: The password used to derive the AES encryption key.
    
    Returns:
    - The decrypted plaintext message.
    """
    # Load the encrypted data (salt, IV, ciphertext) from the provided JSON string
    data = json.loads(encrypted_json)
    
    # Decode the base64 encoded salt, IV, and ciphertext to get the original byte values
    salt = base64.b64decode(data["salt"])
    iv = base64.b64decode(data["iv"])
    ciphertext = base64.b64decode(data["ciphertext"])
    
    # Derive the key using the password and the salt stored with the data
    key = derive_key(password, salt)
    
    # Initialize AESGCM with the derived key
    aesgcm = AESGCM(key)
    
    # Decrypt the ciphertext. The 'None' argument means no associated data for authenticity.
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    
    # Return the decrypted plaintext message as a string
    return plaintext.decode()

# === DEMO ===
if __name__ == "__main__":
    user_password = "supersecurepassword"  # Example user password
    secret_message = "The eagle has landed."  # Example message to be encrypted

    # Show the original plaintext message
    print("Original:", secret_message)
    
    # Encrypt the message using the user's password
    encrypted = encrypt(secret_message, user_password)
    
    # Display the encrypted data as a JSON string
    print("Encrypted JSON:", encrypted)

    # Decrypt the message back using the same password
    decrypted = decrypt(encrypted, user_password)
    
    # Show the decrypted message
    print("Decrypted:", decrypted)
