package ch.oxc.nikea

import com.ionspin.kotlin.crypto.aead.AuthenticatedEncryptionWithAssociatedData
import com.ionspin.kotlin.crypto.hash.crypto_hash_sha256_BYTES
import com.ionspin.kotlin.crypto.hash.crypto_hash_sha512_BYTES
import com.ionspin.kotlin.crypto.signature.InvalidSignatureException
import com.ionspin.kotlin.crypto.signature.Signature
import com.ionspin.kotlin.crypto.signature.crypto_sign_SECRETKEYBYTES
import com.ionspin.kotlin.crypto.signature.crypto_sign_BYTES
import com.ionspin.kotlin.crypto.signature.crypto_sign_PUBLICKEYBYTES

class InvalidSizeException(message: String) : Exception(message)

// TODO add support for ED448
// SignatureAlgo is a wrapper around LibSodium sign_detached
// since Libsodium does not verify the key sizes and instead reads past the buffer size, this wrapper implements these checks
enum class SignatureAlgo(
    val sign: (msg: UByteArray, seck: UByteArray) -> UByteArray,
    val verify: (sig: UByteArray, msg: UByteArray, pubk: UByteArray) -> Boolean
) {
    ED25519(
        { msg, seck ->
            if (seck.size != crypto_sign_SECRETKEYBYTES)
                throw InvalidSizeException("invalid size: ${seck.size}")
            Signature.detached(msg, seck)
        },
        { sig, msg, pubk ->
            if (sig.size != crypto_sign_BYTES)
                throw InvalidSizeException("invalid size: ${sig.size}")
            if (pubk.size != crypto_sign_PUBLICKEYBYTES)
                throw InvalidSizeException("invalid size: ${pubk.size}")
            try {
                Signature.verifyDetached(sig, msg, pubk)
                true
            } catch (_: InvalidSignatureException) {
                false
            }
        })
}

// TODO add support for AES256_GCM(32)
enum class CipherAlgo(
    val keySize: Int,
    val encrypt: (plaintext: UByteArray, ad: UByteArray, nonce: UByteArray, key: UByteArray) -> UByteArray,
    val decrypt: (ciphertextAndTag: UByteArray, ad: UByteArray, nonce: UByteArray, key: UByteArray) -> UByteArray
) {
    // doc: https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
        XCHACHA20_POLY1305(32,
        { plaintext, ad, nonce, key ->
            // any keySize < 32: AeadCorrupedOrTamperedDataException
            // any keySize > 32 gets truncated (enc with sha512 & dec with sha512.copyOf(32) works)
            if (key.size != 32) throw InvalidSizeException("invalid size: ${key.size}")
            AuthenticatedEncryptionWithAssociatedData.xChaCha20Poly1305IetfEncrypt(plaintext, ad, nonce, key)
        },
        { ciphertextAndTag, ad, nonce, key ->
            if (key.size != 32) throw InvalidSizeException("invalid size: ${key.size}")
            AuthenticatedEncryptionWithAssociatedData.xChaCha20Poly1305IetfDecrypt(ciphertextAndTag, ad, nonce, key)
        }
    )
}

// TODO BLAKE2s, BLAKE2b
enum class HashAlgo(val size: Int, val hash: (UByteArray) -> UByteArray) {
    SHA256(crypto_hash_sha256_BYTES, { data -> com.ionspin.kotlin.crypto.hash.Hash.sha256(data) }),
    SHA512(crypto_hash_sha512_BYTES, { data -> com.ionspin.kotlin.crypto.hash.Hash.sha512(data) })
}

// Not every Libsodium wrapper provides ScalarMultiplication.scalarMultiplication(localSeck, remotePubk)
// eg. https://github.com/jedisct1/swift-sodium/issues/136
// doc: https://doc.libsodium.org/key_exchange
// usage: val dhes = config.dh.dh(keys.e.seck, keys.rs)
//enum class DHAlgo(val keySize: Int, val dh: (localSeck: UByteArray, remotePubk: UByteArray) -> UByteArray) {
//    X25519(32, { localSeck, remotePubk -> ScalarMultiplication.scalarMultiplication(localSeck, remotePubk) })
//}
