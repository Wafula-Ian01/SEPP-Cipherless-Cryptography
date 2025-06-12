# SEPP: Superpositional Encrypted Proof Protocol (PoC)

> A conceptual prototype demonstrating epistemic access control over encrypted data using Zero-Knowledge Proofs and Homomorphic Encryption.

## Overview

**SEPP** introduces a quantum-inspired cryptographic scheme where encrypted data remains in an undecidable *superpositional* state until the prover presents valid knowledge. This Proof-of-Concept simulates SEPP logic using standard Python cryptographic libraries.

## Core Concepts

- **Superpositional Encryption**: Encrypted data cannot be decrypted unless the observer demonstrates knowledge through a ZK-style proof.
- **ZK-Gated Key Derivation**: The decryption key is derived only when a valid proof is provided.
- **Quantum-Inspired Epistemology**: Until observed with knowledge, the ciphertext remains undecidable—mirroring Schrödinger’s Cat.

## Getting Started

### Requirements

- Python 3.8+
- Go SDK
- Recommended: virtualenv or conda (not mandatory)

### Running script
```bash
python sepp.py encrypt --message "message" --statement "identity:subject" --proof "s3cr3tPr00f"

```
### Building and Running the Go executable
```bash
go build -o SEPP
./SEPP
