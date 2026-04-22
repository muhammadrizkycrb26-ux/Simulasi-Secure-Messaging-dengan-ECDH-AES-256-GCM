from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
import os

def generate_keypair():
    private = X25519PrivateKey.generate()
    public = private.public_key()
    pub_bytes = public.public_bytes(encoding=serialization.Encoding.Raw,
                                    format=serialization.PublicFormat.Raw)
    return private, pub_bytes

def derive_session_key(shared_secret: bytes, info: bytes = b"session-key") -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    return hkdf.derive(shared_secret)

def encrypt_message(sender_private, recipient_pub_bytes, plaintext: bytes):
    recipient_pub = X25519PublicKey.from_public_bytes(recipient_pub_bytes)
    shared = sender_private.exchange(recipient_pub)
    session_key = derive_session_key(shared)
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    # Sertakan juga kunci publik pengirim agar penerima bisa menghitung shared secret
    sender_pub_bytes = sender_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return {"sender_pub": sender_pub_bytes, "nonce": nonce, "ciphertext": ciphertext}

def decrypt_message(recipient_private, package: dict) -> bytes:
    sender_pub = X25519PublicKey.from_public_bytes(package["sender_pub"])
    shared = recipient_private.exchange(sender_pub)
    session_key = derive_session_key(shared)
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(package["nonce"], package["ciphertext"], None)

# ========== Simulasi ==========
if __name__ == "__main__":
    print("=== ECDH Secure Messaging Simulation ===\n")

    # 1. Generate key pairs
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()

    print(f"[Alice] Public Key: {alice_pub.hex()[:16]}...")
    print(f"[Bob]   Public Key: {bob_pub.hex()[:16]}...")

    # 2. Key exchange (simulasi pertukaran kunci publik)
    # Alice compute shared secret with Bob's public
    shared_alice = alice_priv.exchange(X25519PublicKey.from_public_bytes(bob_pub))
    # Bob compute shared secret with Alice's public
    shared_bob = bob_priv.exchange(X25519PublicKey.from_public_bytes(alice_pub))

    print(f"\n[Shared Secret] Alice: {shared_alice.hex()[:16]}... | Bob: {shared_bob.hex()[:16]}...")
    print(f"Sama? {shared_alice == shared_bob}\n")

    # Derive session key
    session_key_alice = derive_session_key(shared_alice, b"chat-key")
    session_key_bob = derive_session_key(shared_bob, b"chat-key")
    print(f"[Session Key] Alice: {session_key_alice.hex()[:16]}... | Bob: {session_key_bob.hex()[:16]}...")
    print(f"Sama? {session_key_alice == session_key_bob}\n")

    # 3. Alice mengirim pesan
    plaintext = b"Halo Bob, ini pesan rahasia!"
    print(f"[Alice] Pesan asli: {plaintext.decode()}")

    encrypted_pkg = encrypt_message(alice_priv, bob_pub, plaintext)
    print(f"[Alice] Ciphertext: nonce={encrypted_pkg['nonce'].hex()[:8]}... ct={encrypted_pkg['ciphertext'].hex()[:16]}...")

    # 4. Bob mendekripsi
    decrypted = decrypt_message(bob_priv, encrypted_pkg)
    print(f"[Bob]   Terdekripsi: {decrypted.decode()} ✓\n")

    # 5. Buktikan isolasi sesi (kunci baru)
    print("=== Simulasi sesi baru ===")
    alice_priv2, alice_pub2 = generate_keypair()
    bob_priv2, bob_pub2 = generate_keypair()
    shared2 = alice_priv2.exchange(X25519PublicKey.from_public_bytes(bob_pub2))
    session_key2 = derive_session_key(shared2, b"chat-key")
    print(f"Session key baru: {session_key2.hex()[:16]}...")
    print(f"Berbeda dari sebelumnya? {session_key2 != session_key_alice}")

    # Coba dekripsi pesan lama dengan kunci baru (gagal karena decrypt akan raise exception)
    print("\nMencoba dekripsi pesan lama dengan kunci baru (private key berbeda):")
    try:
        # Gunakan private key baru untuk dekripsi paket lama
        decrypt_message(bob_priv2, encrypted_pkg)
    except Exception as e:
        print(f"Gagal (sesuai harapan): {e.__class__.__name__} - pesan lama tidak bisa didekripsi")