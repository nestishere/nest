# Nest

High-assurance secure messaging system (work in progress).

## Phase 0 — Foundations

It is the stage where we proved the basic cryptographic building blocks work:

* Ed25519 keypair generation
* XChaCha20-Poly1305 authenticated encryption
* Correct decryption
* Tamper detection

## Phase 1 — Local Secure Channel

It is the stage where we built a real encrypted chat between two local processes:

* Persistent Ed25519 identity keys
* X25519 key exchange
* Dual-chain symmetric ratchet (forward secrecy)
* XChaCha20-Poly1305 authenticated encryption for every message
* Message counters + basic replay protection
* Clean connection and shutdown handling

Two processes can now securely chat over localhost even if they restart, and each message uses a unique key derived from the ratchet.

## Phase 2 — Store-and-Forward Relay

It is the stage where we made messaging asynchronous:

* Simple relay that stores opaque encrypted blobs
* Client encrypts messages for any public key using sealed boxes
* Client can send encrypted messages to the relay
* Client can later fetch and decrypt pending messages
* Support for multiple identities (client / server)

Users no longer need to be online at the same time. The relay never sees plaintext.
