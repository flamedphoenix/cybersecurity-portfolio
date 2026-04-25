import time
import os
from kyber_py.kyber import Kyber512, Kyber768, Kyber1024
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

RUNS = 50

print("=" * 60)
print("Post-Quantum vs Classical Cryptography Evaluation")
print("=" * 60)

# ── RSA-2048 ────────────────────────────────────────────────
print("\n--- RSA-2048 (Classical) ---")

# Key generation
start = time.perf_counter()
for _ in range(RUNS):
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_public = rsa_private.public_key()
rsa_keygen_ms = (time.perf_counter() - start) / RUNS * 1000

# Encryption (encrypt a 32-byte session key)
session_key = os.urandom(32)
start = time.perf_counter()
for _ in range(RUNS):
    ciphertext_rsa = rsa_public.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
rsa_enc_ms = (time.perf_counter() - start) / RUNS * 1000

# Decryption
start = time.perf_counter()
for _ in range(RUNS):
    rsa_private.decrypt(
        ciphertext_rsa,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
rsa_dec_ms = (time.perf_counter() - start) / RUNS * 1000

pub_bytes = rsa_public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
priv_bytes = rsa_private.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

print(f"  Key generation : {rsa_keygen_ms:.2f} ms")
print(f"  Encryption     : {rsa_enc_ms:.2f} ms")
print(f"  Decryption     : {rsa_dec_ms:.2f} ms")
print(f"  Public key size : {len(pub_bytes)} bytes")
print(f"  Private key size: {len(priv_bytes)} bytes")
print(f"  Ciphertext size : {len(ciphertext_rsa)} bytes")

# ── Kyber512 ────────────────────────────────────────────────
print("\n--- CRYSTALS-Kyber512 (Post-Quantum, NIST Level 1) ---")

start = time.perf_counter()
for _ in range(RUNS):
    pk, sk = Kyber512.keygen()
keygen_ms = (time.perf_counter() - start) / RUNS * 1000

start = time.perf_counter()
for _ in range(RUNS):
    key, ct = Kyber512.encaps(pk)
enc_ms = (time.perf_counter() - start) / RUNS * 1000

start = time.perf_counter()
for _ in range(RUNS):
    Kyber512.decaps(sk, ct)
dec_ms = (time.perf_counter() - start) / RUNS * 1000

print(f"  Key generation : {keygen_ms:.2f} ms")
print(f"  Encapsulation  : {enc_ms:.2f} ms")
print(f"  Decapsulation  : {dec_ms:.2f} ms")
print(f"  Public key size : {len(pk)} bytes")
print(f"  Secret key size : {len(sk)} bytes")
print(f"  Ciphertext size : {len(ct)} bytes")

# ── Kyber1024 ───────────────────────────────────────────────
print("\n--- CRYSTALS-Kyber1024 (Post-Quantum, NIST Level 5) ---")

start = time.perf_counter()
for _ in range(RUNS):
    pk, sk = Kyber1024.keygen()
keygen_ms = (time.perf_counter() - start) / RUNS * 1000

start = time.perf_counter()
for _ in range(RUNS):
    key, ct = Kyber1024.encaps(pk)
enc_ms = (time.perf_counter() - start) / RUNS * 1000

start = time.perf_counter()
for _ in range(RUNS):
    Kyber1024.decaps(sk, ct)
dec_ms = (time.perf_counter() - start) / RUNS * 1000

print(f"  Key generation : {keygen_ms:.2f} ms")
print(f"  Encapsulation  : {enc_ms:.2f} ms")
print(f"  Decapsulation  : {dec_ms:.2f} ms")
print(f"  Public key size : {len(pk)} bytes")
print(f"  Secret key size : {len(sk)} bytes")
print(f"  Ciphertext size : {len(ct)} bytes")

# ── Correctness check ───────────────────────────────────────
print("\n--- Correctness Check ---")
pk, sk = Kyber512.keygen()
shared_key_sender, ct = Kyber512.encaps(pk)
shared_key_receiver = Kyber512.decaps(sk, ct)
print(f"  Keys match: {shared_key_sender == shared_key_receiver}")

print("\n" + "=" * 60)
print("Evaluation complete.")
print("=" * 60)
