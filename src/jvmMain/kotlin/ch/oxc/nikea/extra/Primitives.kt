@file:OptIn(ExperimentalUnsignedTypes::class)

package ch.oxc.nikea.extra

import com.ionspin.kotlin.crypto.pwhash.PasswordHash
import com.ionspin.kotlin.crypto.pwhash.crypto_pwhash_MEMLIMIT_MODERATE
import com.ionspin.kotlin.crypto.pwhash.crypto_pwhash_OPSLIMIT_MODERATE
import com.ionspin.kotlin.crypto.pwhash.crypto_pwhash_argon2id_ALG_ARGON2ID13
import java.util.*

interface KeyDerivationAlgo {
    val name: String

    fun derive(password: String): String

    fun derive(password: String, args: String): UByteArray
}

object Argon2id : KeyDerivationAlgo {
    override val name = "argon2id"

    override fun derive(password: String): String {
        // produces an output similar to this: $argon2id$v=19$m=262144,t=3,p=1$4ljukisxOQNKt7uIIe4gBw$rQG5UGTyvIyjwvXMJQRD0hFx5UlXHU3WWZBX3TrS2HI
        // i.e. it contains all parameters and can be saved like this
        // ascii encoded, "the output string is zero-terminated" -> remove trailing zeroes
        return PasswordHash.str(password, crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE)
            .dropLastWhile { it.compareTo(0u) == 0 }.toUByteArray().toByteArray().toUtf8()
    }

    /**
     * derive using known arguments
     */
    override fun derive(password: String, args: String): UByteArray {
        val elements = args.split('$')
        if (elements[1] != name) throw IllegalArgumentException("Argon2id: Unexpected kdf algorithm: '${elements[1]}'")
        val version = elements[2].split('=')[1].toInt()
        if (version != 19) throw IllegalArgumentException("Argon2id: Unexpected version: '${elements[2]}'")
        val params = elements[3].split(',')
        val m = params[0].split('=')[1].toInt()
        val t = params[1].split('=')[1].toInt()
        val p = params[2].split('=')[1].toInt()
        if (p != 1) throw IllegalArgumentException("Argon2id: Unexpected parallelism: '$p'")
        val salt = Base64.getDecoder().decode(elements[4])

        // str doesn't accept salt
        // libsodium uses bytes, not kibibytes
        // pwhash, in comparison to str, only returns the actual key derived
        val derivedKey = PasswordHash.pwhash(
            32, password, salt.toUByteArray(), t.toULong(), m * 1024, crypto_pwhash_argon2id_ALG_ARGON2ID13
        )
        return derivedKey
    }
}
