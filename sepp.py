import argparse
import hashlib
import os

# === Core SEPP Cipherless Logic === #

def zk_verify(statement: str, proof: str) -> bool:
    expected = hashlib.sha256(statement.encode()).hexdigest()
    return expected.endswith(proof)

def create_SES(plaintext: str, statement: str, proof: str):
    if not zk_verify(statement, proof):
        raise ValueError("Invalid ZK proof")
    tau = os.urandom(16)
    gamma = hashlib.sha256((plaintext + proof).encode() + tau).hexdigest()
    entangled = hashlib.pbkdf2_hmac('sha256', plaintext.encode(), gamma.encode(), 100000)
    return {"entangled": entangled, "gamma": gamma, "proof": proof, "tau": tau}

def collapse_SES(ses: dict, statement: str, proof_attempt: str, plaintext_guess: str):
    if not zk_verify(statement, proof_attempt):
        return None
    gamma_check = hashlib.sha256((plaintext_guess + proof_attempt).encode() + ses["tau"]).hexdigest()
    entangled_check = hashlib.pbkdf2_hmac('sha256', plaintext_guess.encode(), gamma_check.encode(), 100000)
    if entangled_check == ses["entangled"]:
        return plaintext_guess
    return None

# === CLI Tool === #

def main():
    parser = argparse.ArgumentParser(description="SEPP Cipherless CLI Tool")
    subparsers = parser.add_subparsers(dest="command")

    encrypt_parser = subparsers.add_parser("encrypt", help="Create Superpositional Encrypted State")
    encrypt_parser.add_argument("--message", required=True, help="Message to encrypt")
    encrypt_parser.add_argument("--statement", required=True, help="ZK statement")
    encrypt_parser.add_argument("--proof", required=True, help="ZK proof")

    decrypt_parser = subparsers.add_parser("decrypt", help="Collapse SES")
    decrypt_parser.add_argument("--entangled_file", required=True, help="Path to SES state file")
    decrypt_parser.add_argument("--statement", required=True, help="ZK statement")
    decrypt_parser.add_argument("--proof", required=True, help="ZK proof attempt")
    decrypt_parser.add_argument("--guess", required=True, help="Plaintext guess")

    args = parser.parse_args()

    if args.command == "encrypt":
        ses = create_SES(args.message, args.statement, args.proof)
        with open("ses_state.bin", "wb") as f:
            f.write(ses["entangled"] + b"||" + ses["gamma"].encode() + b"||" + ses["tau"])
        print("Cipherless SES created.")
        print("Gamma:", ses["gamma"])
        print("Tau:", ses["tau"].hex())
        print("State saved to ses_state.bin")

    elif args.command == "decrypt":
        with open(args.entangled_file, "rb") as f:
            data = f.read().split(b"||")
            entangled, gamma, tau = data[0], data[1].decode(), data[2]
        ses = {"entangled": entangled, "gamma": gamma, "proof": args.proof, "tau": tau}
        result = collapse_SES(ses, args.statement, args.proof, args.guess)
        if result:
            print("Decryption successful. Collapsed state:")
            print(result)
        else:
            print("Failed to collapse SES. Invalid proof or incorrect guess.")

if __name__ == "__main__":
    main()
