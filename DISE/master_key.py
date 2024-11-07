import secrets

class MasterKey:
    def __init__(self):
        self.keys = []  # Les clés secrètes des différentes parties

    def key_gen(self, n):
        # Générer 'n' clés secrètes (16 bytes chacun pour la compatibilité avec AES-128)
        self.keys = [secrets.token_bytes(16) for _ in range(n)]
        print(f"Generated {n} secret keys:")
        for i, key in enumerate(self.keys):
            print(f"Party {i}: Key = {key.hex()}")
