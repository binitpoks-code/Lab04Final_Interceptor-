import hashlib
import os

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def int_to_bytes(n: int) -> bytes:
    length = (n.bit_length() + 7) // 8 or 1
    return n.to_bytes(length, byteorder='big')

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

class SecurePRNG:
    def __init__(self, seed: bytes):
        self.state = hashlib.sha256(seed).digest()

    def generate(self, n: int) -> bytes:
        keystream = b""
        while len(keystream) < n:
            block = hashlib.sha256(b"output:" + self.state).digest()
            keystream += block
            self.state = hashlib.sha256(b"state:" + self.state).digest()
        return keystream[:n]

def stream_cipher(key_prng: SecurePRNG, data: bytes) -> bytes:
    return xor_bytes(data, key_prng.generate(len(data)))

class Entity:
    def __init__(self, name: str, p: int = 23, g: int = 5):
        self.name = name
        self.p = p
        self.g = g
        self.private_key = bytes_to_int(os.urandom(16)) % (p - 2) + 2
        self.public_key = pow(g, self.private_key, p)
        self.prng = None

    def get_public_hex(self) -> str:
        return hex(self.public_key)

    def establish_session(self, peer_pub_hex: str):
        shared_secret = pow(int(peer_pub_hex, 16), self.private_key, self.p)
        self.prng = SecurePRNG(int_to_bytes(shared_secret))

    def send_message(self, plaintext: str) -> bytes:
        return stream_cipher(self.prng, plaintext.encode('utf-8'))

    def receive_message(self, ciphertext: bytes) -> str:
        return stream_cipher(self.prng, ciphertext).decode('utf-8', errors='replace')

class Mallory:
    def __init__(self, p: int = 23, g: int = 5):
        self.p = p
        self.g = g
        self.priv_alice = bytes_to_int(os.urandom(16)) % (p - 2) + 2
        self.pub_alice = pow(g, self.priv_alice, p)
        self.priv_bob = bytes_to_int(os.urandom(16)) % (p - 2) + 2
        self.pub_bob = pow(g, self.priv_bob, p)
        self.prng_alice = None
        self.prng_bob = None

    def intercept_key_exchange(self, alice_pub_hex: str, bob_pub_hex: str):
        s_alice = pow(int(alice_pub_hex, 16), self.priv_alice, self.p)
        self.prng_alice = SecurePRNG(int_to_bytes(s_alice))
        s_bob = pow(int(bob_pub_hex, 16), self.priv_bob, self.p)
        self.prng_bob = SecurePRNG(int_to_bytes(s_bob))
        return hex(self.pub_alice), hex(self.pub_bob)

    def modify_traffic(self, ciphertext_from_alice: bytes, old_word: str, new_word: str) -> bytes:
        plaintext = stream_cipher(self.prng_alice, ciphertext_from_alice).decode('utf-8')
        print(f"[Mallory Intercepted]: {plaintext}")
        modified_plaintext = plaintext.replace(old_word, new_word)
        print(f"[Mallory Modified]: {modified_plaintext}")
        return stream_cipher(self.prng_bob, modified_plaintext.encode('utf-8'))

def run_scenario_a():
    print("=" * 60)
    print("SCENARIO A: Secure Communication (No Interceptor)")
    print("=" * 60)
    alice = Entity("Alice")
    bob = Entity("Bob")
    alice.establish_session(bob.get_public_hex())
    bob.establish_session(alice.get_public_hex())
    message = "Hello Bob! Please transfer 1000 credits."
    print(f"Original text: {message}")
    ciphertext = alice.send_message(message)
    print(f"Ciphertext hex: {ciphertext.hex()}")
    decrypted = bob.receive_message(ciphertext)
    print(f"Decrypted text: {decrypted}\n")

def run_scenario_b():
    print("=" * 60)
    print("SCENARIO B: Man-in-the-Middle Attack (Mallory)")
    print("=" * 60)
    alice = Entity("Alice")
    bob = Entity("Bob")
    mallory = Mallory()
    fake_bob_pub, fake_alice_pub = mallory.intercept_key_exchange(
        alice.get_public_hex(), bob.get_public_hex()
    )
    alice.establish_session(fake_bob_pub)
    bob.establish_session(fake_alice_pub)
    message = "Hello Bob! Please transfer 1000 credits."
    print(f"Alice's original text: {message}")
    ciphertext = alice.send_message(message)
    print(f"Alice's ciphertext hex: {ciphertext.hex()}")
    modified_ciphertext = mallory.modify_traffic(ciphertext, "1000", "9000")
    print(f"Forwarded ciphertext: {modified_ciphertext.hex()}")
    decrypted = bob.receive_message(modified_ciphertext)
    print(f"Bob's decrypted text: {decrypted}")
    print("Bob decrypts successfully: no authentication detects the change.\n")

if __name__ == "__main__":
    run_scenario_a()
    input("Press Enter to run Scenario B...")
    run_scenario_b()