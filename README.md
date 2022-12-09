# Nikea: Non-Interactive Key Agreement
Nikea provides end-to-end encrypted communication with offline handshake establishment.

Handshake keys are selected by a server, but clients verify them using trust-on-first-use signatures.
This allows for one of the peers to be offline during establishment (and initial use) of the handshake.

Built using [Libsodium bindings for Kotlin Multiplatform](https://github.com/ionspin/kotlin-multiplatform-libsodium), it provides the following features:
- **Key Agreement** using X25519 Elliptic Curve Diffie-Hellman
- **Perfect Forward Secrecy** by using unique ephemeral keys in every handshake and a hash ratchet while active
- **Non-interactive** handshake establishment even if the peer is offline (through pre-shared (ephemeral) keys)
- **Trust** through a trust-on-first-use (tofu) signature verification mechanism for all peer keys (Ed25519)

**Disclaimer**: this is a personal project and not safe for use in production.

## Motivation
From the [Noise Protocol Framework spec](http://noiseprotocol.org/noise.html):
> Note that the second message's payload may contain a zero-length plaintext, but the payload ciphertext will still contain authentication data (such as an authentication tag or "synthetic IV"),
> since encryption is with an AEAD mode. The second message's payload can also be used to deliver certificates for the responder's static public key.

While this is advantageous for 0-RTT messages, it also has a disadvantage: both peers need to be online at the same time to exchange messages .
This is because the `k` value of the `CipherState` is not meant to be persisted (i.e. ephemeral keys & handshake states are deleted when going offline).

## Info
A _noise_ `KK` handshake:
```
-> s
<- s
...
-> e, es, ee
<- e, ee, se
```

A _nikea_ handshake:
```
-> s, e, identk, sig(s), sig(e)
<- s, e, itentk, sig(s), sig(e)
...
- es, ss, ee, se
```

All this library does is a 4x Diffie-Hellman key agreement plus some signature verification and hash ratcheting.

Since there is no negotiation or interactive communication to complete the handshake, there are no chaining keys (-> no hkdf), etc.
A server acts as middleman and provides the keys & signatures, the clients just verify.

## TODO
- more negative tests
- `Config` is of no use since the only one of each algorithm is implemented
  - Libsodium does not provide `X448` or `Ed448` and the Libsodium bindings do not provide `Blake2b`
- how do WhatsApp/others persist the handshake state? [Whitepaper](https://www.whatsapp.com/security/WhatsApp-Security-Whitepaper.pdf)

## Comparison
- [noise-java](https://github.com/Auties00/noise-java) ships with a custom (?) Java implementation of Curve25519
  - Nikea uses [Libsodium bindings for Kotlin Multiplatform](https://github.com/ionspin/kotlin-multiplatform-libsodium) for Curve25519
- Libsodium's `crypto_box()` (`scalarmult()` + hash + `secretbox()`) does not implement hash ratcheting, so this lib is different

## Usage
[Publish your library to the local Maven repository](https://kotlinlang.org/docs/multiplatform-library.html#publish-your-library-to-the-local-maven-repository)

## Algorithms
### Ed25519 & X25519
Ed25519 is a deterministic signature scheme & X25519 is an Elliptic Curve Diffie-Hellman (ECDH) key agreement scheme. Both use Curve25519 and are comparably fast and efficient.
In both cases, the private keys are simply 32 random bytes (_seed_). From this, a public key for each keypair type can be generated.
While public keys can be translated between both schemes, it's nonetheless recommended to use different private keys for both operations.

Ed25519 uses a curve which is birationally equivalent to Curve25519.
More generally, the EdDSA (Edwards-curve Digital Signature Algorithm) approach can be considered as a variant of ElGamal signatures (such as Schnorr or DSA).
Importantly, they all follow the __hash-then-sign__ ([go](https://cs.opensource.google/go/go/+/refs/tags/go1.19.2:src/crypto/ed25519/ed25519.go;l=167)) approach, meaning that they can sign arbitrary length messages by transforming them to a fixed-size representation first.
For Ed25519, the default hash algo is SHA-512. Most Libsodium wrappers do not provide the ability to change this easily.

Resources:
- [cryptobook: EdDSA and Ed25519](https://cryptobook.nakov.com/digital-signatures/eddsa-and-ed25519)
- [cryptobook: EdDSA: Sign / Verify - Examples](https://cryptobook.nakov.com/digital-signatures/eddsa-sign-verify-examples)
- [Filippo Valsorda: USING ED25519 SIGNING KEYS FOR ENCRYPTION](https://words.filippo.io/using-ed25519-keys-for-encryption/)
- [A Deep dive into Ed25519 Signatures](https://cendyne.dev/posts/2022-03-06-ed25519-signatures.html)

Libsodium notes:
- `crypto_box()`: implements ECDH in Montgomery form Curve25519 (fast for variable base scalar mult. - eg. DH: X25519)
  - convert private key to public key: `crypto_scalarmult_base` ([doc](https://libsodium.gitbook.io/doc/advanced/scalar_multiplication))
- `crypto_sign()`: implements EdDSA in Twisted Edwards form Curve25519 (fast for fixed base scalar multi. - eg. signing: Ed25519)
  - convert private key to public key: `crypto_sign_seed_keypair` ([doc](https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures))

### XChaCha20-Poly1305
A secret key algorithm for encryption. Without hardware acceleration, it's usually faster than AES-256-GCM while proving a similar degree of security.

### SHA-512 or BLAKE2b
Used for key derivation after DH and the hash ratchet during communication. Some Libsodium wrappers don't provide BLAKE2b.

## Resources
- Briar: [Bramble Handshake Protocol](https://code.briarproject.org/briar/briar-spec/blob/master/protocols/BHP.md)
- [noise spec](http://noiseprotocol.org/noise.html)
  - [KK variant in LibHydrogen](https://github.com/jedisct1/libhydrogen/wiki/KK-variant)
- [WhatsApp Security Whitepaper]() & [WhatsApp Security Paper Analysis](https://courses.csail.mit.edu/6.857/2016/files/36.pdf)
