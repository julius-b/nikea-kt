@file:OptIn(ExperimentalUnsignedTypes::class)

package ch.oxc.nikea.extra

import ch.oxc.nikea.*
import java.util.*

enum class VaultKeyAlgo(val cipher: CipherAlgo) {
    XChaCha20Poly1305(XChaCha20Poly1305Cipher)
}

/**
 * A [VaultKey] is principally a secret key [seckClr] plus its backup.
 * This backup of the key is encrypted using a Key Encryption Key (KEK), which is derived from the user password.
 */
data class VaultKey(
    val algo: VaultKeyAlgo, val args: String, val seckClr: UByteArray, val seckEnc: UByteArray
) {
    fun encrypt(plaintext: UByteArray, ad: UByteArray, nonce: UByteArray) =
        algo.cipher.encrypt(plaintext, ad, nonce, seckClr)

    fun decrypt(ciphertextAndTag: UByteArray, ad: UByteArray, nonce: UByteArray) =
        algo.cipher.decrypt(ciphertextAndTag, ad, nonce, seckClr)

    companion object {
        /**
         * The [seckEnc] corresponds to ciphertextAndTag. The nonce used is prepended.
         *
         * @param password the root key material, e.g. a user password
         */
        fun new(
            password: String,
            ad: UByteArray,
            algo: VaultKeyAlgo = VaultKeyAlgo.XChaCha20Poly1305,
            kdf: KeyDerivationAlgo = Argon2id,
            kekNonce: UByteArray = algo.cipher.genNonce()
        ): VaultKey {
            // kek: derive secure key from password
            val kekStr = kdf.derive(password)
            val lastIdx = kekStr.lastIndexOf('$')

            // decoded kek
            val kek = Base64.getDecoder().decode(kekStr.substring(lastIdx + 1)).toUByteArray()

            // the vault key
            val seckClr = algo.cipher.genKey()
            val rawSeckEnc = algo.cipher.encrypt(seckClr, ad, kekNonce, kek)

            // libsodium accepts bytes, not kibibytes - but the string is still in kibibytes
            val args = kekStr.substring(0, lastIdx) // excludes last '$'

            return VaultKey(algo, args, seckClr, kekNonce + rawSeckEnc)
        }

        fun recover(
            password: String,
            args: String,
            seckEnc: UByteArray,
            ad: UByteArray,
            algo: VaultKeyAlgo = VaultKeyAlgo.XChaCha20Poly1305,
            kdf: KeyDerivationAlgo = Argon2id
        ): VaultKey {
            // generate same encKey as was used to encrypt the encryption key
            val kek = kdf.derive(password, args)

            val nonceSize = 24
            val nonce = seckEnc.copyOf(nonceSize)
            val rawSeckEnc = seckEnc.copyOfRange(nonceSize, seckEnc.size)
            val seckClr = algo.cipher.decrypt(rawSeckEnc, ad, nonce, kek)

            return VaultKey(algo, args, seckClr, seckEnc)
        }
    }
}

enum class IdentityKeyAlgo(val signer: SignatureAlgo) {
    Ed25519(Ed25519Signature)
}

/**
 * Every user publishes an [IdentityKey] akin to a self-signed CA certificate (includes proof of secret key ownership)
 */
data class IdentityKey(
    val algo: IdentityKeyAlgo, val keys: KeyPair, val pubkSigned: UByteArray
) {
    companion object {
        fun new(algo: IdentityKeyAlgo = IdentityKeyAlgo.Ed25519): IdentityKey {
            val keyPair = algo.signer.genKeyPair()
            val pubkSigned = algo.signer.sign(keyPair.pubk, keyPair.seck)
            return IdentityKey(algo, keyPair, pubkSigned)
        }
    }
}

enum class KexKeyAlgo(val dh: DHAlgo) {
    X25519(X25519DH)
}

/**
 * Key Exchange Key.
 */
data class KexKey(
    val algo: KexKeyAlgo,
    val sigAlgo: IdentityKeyAlgo,
    val keys: KeyPair,
    val pubkSigned: UByteArray,
) {
    companion object {
        fun new(
            identitySeck: UByteArray,
            algo: KexKeyAlgo = KexKeyAlgo.X25519,
            sigAlgo: IdentityKeyAlgo = IdentityKeyAlgo.Ed25519
        ): KexKey {
            val keyPair = algo.dh.genKeyPair()

            val pubkSigned = sigAlgo.signer.sign(keyPair.pubk, identitySeck)
            return KexKey(algo, sigAlgo, keyPair, pubkSigned)
        }
    }
}
