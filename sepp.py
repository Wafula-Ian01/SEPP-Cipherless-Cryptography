import argparse
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# === Core SEPP Logic === #

def encrypt_aes(key: bytes, plaintext: str) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    return iv + encryptor.update(padded) + encryptor.finalize()

def decrypt_aes(key: bytes, ciphertext: bytes) -> str:
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted) + unpadder.finalize()

def zk_verify(statement: str, proof: str) -> bool:
    expected = hashlib.sha256(statement.encode()).hexdigest()
    return expected.endswith(proof)

def derive_key_from_proof(proof: str) -> bytes:
    return hashlib.sha256(proof.encode()).digest()

def create_SES(plaintext: str, statement: str, proof: str):
    if not zk_verify(statement, proof):
        raise ValueError("Invalid ZK proof")
    derived_key = derive_key_from_proof(proof)
    ciphertext = encrypt_aes(derived_key, plaintext)
    tau = os.urandom(16)
    gamma = hashlib.sha256(ciphertext + proof.encode() + tau).hexdigest()
    return {"ciphertext": ciphertext, "gamma": gamma, "proof": proof, "tau": tau}

def collapse_SES(ses: dict, statement: str, proof_attempt: str):
    if not zk_verify(statement, proof_attempt):
        return None
    derived_key = derive_key_from_proof(proof_attempt)
    try:
        return decrypt_aes(derived_key, ses["ciphertext"]).decode()
    except:
        return None

# === CLI Tool === #

def main():
    parser = argparse.ArgumentParser(description="SEPP CLI Tool")
    subparsers = parser.add_subparsers(dest="command")

    encrypt_parser = subparsers.add_parser("encrypt", help="Create Superpositional Encrypted State")
    encrypt_parser.add_argument("--message", required=True, help="Message to encrypt")
    encrypt_parser.add_argument("--statement", required=True, help="ZK statement")
    encrypt_parser.add_argument("--proof", required=True, help="ZK proof")

    decrypt_parser = subparsers.add_parser("decrypt", help="Collapse SES")
    decrypt_parser.add_argument("--ciphertext_file", required=True, help="Path to ciphertext file")
    decrypt_parser.add_argument("--statement", required=True, help="ZK statement")
    decrypt_parser.add_argument("--proof", required=True, help="ZK proof attempt")

    args = parser.parse_args()

    if args.command == "encrypt":
        ses = create_SES(args.message, args.statement, args.proof)
        with open("ses_ciphertext.bin", "wb") as f:
            f.write(ses["ciphertext"])
        print("✅ SES created successfully.")
        print("Gamma:", ses["gamma"])
        print("Tau:", ses["tau"].hex())
        print("Ciphertext saved to ses_ciphertext.bin")

    elif args.command == "decrypt":
        with open(args.ciphertext_file, "rb") as f:
            ciphertext = f.read()
        ses = {"ciphertext": ciphertext, "proof": args.proof, "tau": b"", "gamma": ""}
        result = collapse_SES(ses, args.statement, args.proof)
        if result:
            print("Decryption successful. Collapsed state:")
            print(result)
        else:
            print("Failed to collapse SES. Invalid proof or corrupted state.")

if __name__ == "__main__":
    main()
