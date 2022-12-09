@file:OptIn(ExperimentalUnsignedTypes::class)

package ch.oxc.nikea

import com.ionspin.kotlin.crypto.aead.AuthenticatedEncryptionWithAssociatedData
import com.ionspin.kotlin.crypto.box.Box
import com.ionspin.kotlin.crypto.hash.crypto_hash_sha256_BYTES
import com.ionspin.kotlin.crypto.hash.crypto_hash_sha512_BYTES
import com.ionspin.kotlin.crypto.signature.*
import com.ionspin.kotlin.crypto.util.LibsodiumRandom

// TODO replace by illegalargumentexception or extend it or rename to Illegal...
class InvalidSizeException(message: String) : Exception(message)

// TODO add support for ED448
interface SignatureAlgo {
    fun genKeyPair(): KeyPair

    fun sign(msg: UByteArray, seck: UByteArray): UByteArray

    fun verify(sig: UByteArray, msg: UByteArray, pubk: UByteArray): Boolean
}

// Ed25519Signature is a wrapper around LibSodium sign_detached
// since Libsodium does not verify the key sizes and instead reads past the buffer size, so this wrapper implements these checks
object Ed25519Signature : SignatureAlgo {
    override fun genKeyPair(): KeyPair {
        // alt: Signature.seedKeypair(LibsodiumRandom.buf(crypto_sign_SEEDBYTES))
        val keyPair = Signature.keypair()
        return KeyPair(keyPair.secretKey, keyPair.publicKey)
    }

    override fun sign(msg: UByteArray, seck: UByteArray): UByteArray {
        if (seck.size != crypto_sign_SECRETKEYBYTES) throw InvalidSizeException("invalid size: ${seck.size}")
        return Signature.detached(msg, seck) // .copyOf(crypto_sign_BYTES)
    }

    override fun verify(sig: UByteArray, msg: UByteArray, pubk: UByteArray): Boolean {
        if (sig.size != crypto_sign_BYTES) throw InvalidSizeException("invalid size: ${sig.size}")
        if (pubk.size != crypto_sign_PUBLICKEYBYTES) throw InvalidSizeException("invalid size: ${pubk.size}")
        return try {
            Signature.verifyDetached(sig, msg, pubk)
            true
        } catch (_: InvalidSignatureException) {
            false
        }
    }
}

interface DHAlgo {
    val secretKeySize: Int

    fun genKeyPair(): KeyPair
}

object X25519DH : DHAlgo {
    override val secretKeySize = 32

    override fun genKeyPair(): KeyPair {
        // Box.keypair generates a X25519 keypair: https://doc.libsodium.org/advanced/ed25519-curve25519
        // libsodium note: If you can afford it, using distinct keys for signing and for encryption is still highly recommended.
        /*val tmpSigKey = Signature.keypair()
        val keyPair = KeyPair(
            Signature.ed25519SkToCurve25519(tmpSigKey.secretKey),
            Signature.ed25519PkToCurve25519(tmpSigKey.publicKey)
        )*/
        val keyPair = Box.keypair()
        return KeyPair(keyPair.secretKey, keyPair.publicKey)
    }
}

// TODO add support for AES256_GCM(32)
interface CipherAlgo {
    val keySize: Int
    val nonceSize: Int

    fun genKey(): UByteArray

    fun genNonce(): UByteArray

    fun encrypt(plaintext: UByteArray, ad: UByteArray, nonce: UByteArray, key: UByteArray): UByteArray

    fun decrypt(ciphertextAndTag: UByteArray, ad: UByteArray, nonce: UByteArray, key: UByteArray): UByteArray
}

// doc: https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
object XChaCha20Poly1305Cipher : CipherAlgo {
    override val keySize = 32
    override val nonceSize = 24

    override fun genKey() = LibsodiumRandom.buf(keySize)

    override fun genNonce() = LibsodiumRandom.buf(nonceSize)

    override fun encrypt(plaintext: UByteArray, ad: UByteArray, nonce: UByteArray, key: UByteArray): UByteArray {
        // if key.size < 32: AeadCorrupedOrTamperedDataException
        // if key.size > 32: it gets truncated (enc with <sha512> & dec with <sha512>.copyOf(32) works)
        if (key.size != 32) throw InvalidSizeException("invalid size: ${key.size}")
        return AuthenticatedEncryptionWithAssociatedData.xChaCha20Poly1305IetfEncrypt(plaintext, ad, nonce, key)
    }

    override fun decrypt(ciphertextAndTag: UByteArray, ad: UByteArray, nonce: UByteArray, key: UByteArray): UByteArray {
        if (key.size != 32) throw InvalidSizeException("invalid size: ${key.size}")
        return AuthenticatedEncryptionWithAssociatedData.xChaCha20Poly1305IetfDecrypt(ciphertextAndTag, ad, nonce, key)
    }
}

// TODO BLAKE2s, BLAKE2b
enum class HashAlgo(val size: Int, val hash: (UByteArray) -> UByteArray) {
    SHA256(crypto_hash_sha256_BYTES, { data -> com.ionspin.kotlin.crypto.hash.Hash.sha256(data) }), SHA512(
        crypto_hash_sha512_BYTES,
        { data -> com.ionspin.kotlin.crypto.hash.Hash.sha512(data) })
}

// Not every Libsodium wrapper provides ScalarMultiplication.scalarMultiplication(localSeck, remotePubk)
// eg. https://github.com/jedisct1/swift-sodium/issues/136
// doc: https://doc.libsodium.org/key_exchange
// usage: val dhes = config.dh.dh(keys.e.seck, keys.rs)
//enum class DHAlgo(val keySize: Int, val dh: (localSeck: UByteArray, remotePubk: UByteArray) -> UByteArray) {
//    X25519(32, { localSeck, remotePubk -> ScalarMultiplication.scalarMultiplication(localSeck, remotePubk) })
//}

object Random {
    fun gen(bytes: Int) = LibsodiumRandom.buf(bytes)
}
