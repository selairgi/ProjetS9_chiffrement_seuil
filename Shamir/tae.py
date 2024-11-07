from Crypto.Cipher import AES

class TAE:
    def __init__(self, master_key):
        self.master_key = master_key

    def encrypt(self, message):
        """
        Encrypts a message with authenticated encryption.
        Parameters:
            message: Message to encrypt
        Returns:
            (ciphertext, tag, nonce)
        """
        key = self.master_key.keys[0]  # Using the first key for simplicity
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        return ciphertext, tag, cipher.nonce

    def decrypt(self, ciphertext, tag, nonce):
        """
        Decrypts a message with authenticated encryption.
        Parameters:
            ciphertext: Encrypted message
            tag: Authentication tag
            nonce: Nonce used for encryption
        Returns:
            Decrypted message
        """
        key = self.master_key.keys[0]  # Using the same key
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
