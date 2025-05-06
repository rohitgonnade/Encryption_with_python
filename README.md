# Encryption_with_python

## Deriving AES encryption/decryption key using user password

The encryption key is derived from the user password and salt using the **PBKDF2 (Password-Based Key Derivation Function 2)** algorithm. Here's how it works:

1. **Password and Salt**: The user's password and a randomly generated salt are input to the PBKDF2HMAC function.

   * The **salt** is a random string of bytes, ensuring that even if two users have the same password, their keys will still be different.

2. **Key Derivation**:

   * The PBKDF2 algorithm is used to generate a cryptographic key based on the password and salt.
   * **SHA-256** is used as the hashing algorithm within PBKDF2.
   * The function applies multiple iterations (default is 100,000) of the hash function to make it more computationally expensive and harder to brute-force.

3. **Generated Key**: The output of the PBKDF2HMAC function is the derived cryptographic key, which is used for encryption and decryption operations (in this case, AES encryption).

This key is **not the same as the user password**, but it is derived from it, and it will be used to encrypt and decrypt data securely.

---

### Key Steps in Code:

```python
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),  # SHA-256 hash function
    length=32,  # The length of the derived key (256 bits for AES-256)
    salt=salt,  # Salt used to make the key derivation unique
    iterations=iterations,  # Number of iterations to make key derivation slow and secure
    backend=default_backend()  # Cryptographic backend to use for operations
)

# Derive the key (this is a 256-bit AES key)
derived_key = kdf.derive(password.encode())  # The password is encoded to bytes
```



In this code:

* The **salt** ensures that the same password will result in a different key each time it's used.
* The **iterations** make it computationally expensive to generate the key, protecting against brute-force attacks.

The derived key will then be used with AES encryption (AES-GCM in this case) for encrypting and decrypting data securely.

----

## 🔑 Why decryption still works with a different salt each time:

Even though the salt is random each time, **you store it alongside the encrypted data**. That way, when the user wants to decrypt something, you:

1. **Retrieve the stored salt** (which was used during encryption),
2. Use the user’s password + that specific salt to re-derive the same key,
3. Decrypt the data with that key.

---

### 🔁 Think of it like this:

For each message, you're doing:

```python
salt = os.urandom(16)
key = derive_key(password, salt)
ciphertext = encrypt(data, key)
store(salt, ciphertext)
```

Then during decryption:

```python
salt = load_stored_salt()
key = derive_key(password, salt)
data = decrypt(ciphertext, key)
```

You **don’t reuse the salt** — you just **store it per message or file**. That way, even if every piece of data has a different salt (and thus different keys), each one can still be decrypted because its salt is known.

---

#### ✅ Summary:

* Salt = public
* Password = secret
* Key = derived from both
* Salt must be saved with the data for decryption

---

## ✅ Requirements

Install the required library:

```
pip install cryptography
```
