@file:OptIn(ExperimentalUnsignedTypes::class)

package ch.oxc.nikea

val AD = UByteArray(0)

enum class CipherStateMode {
    RXTX, RX, TX
}

class IllegalCryptoOperation(mode: CipherStateMode) : RuntimeException("Operation not allowed with mode: $mode")

/**
 * A [CipherState] represents the current ratchet for rx or tx.
 *
 * The result of a successful [Handshake] consists of two [CipherState]s. That way, messages can be encrypted without
 * modifying the state (k/n) of the decrypt ratchet.
 *
 * @param config determines the [HashAlgo] & [CipherAlgo] used
 * @param mode determines whether this [CipherState] is used for encryption or decryption
 * @param k initial key used
 */
@OptIn(ExperimentalUnsignedTypes::class)
class CipherState(private val config: Config, private val mode: CipherStateMode, var k: UByteArray) {

    init {
        if (k.size != 64) throw IllegalArgumentException("CipherState: unexpected key size: ${k.size}")
    }

    var n: ULong = 0UL
        private set

    private fun ratchet(): UByteArray {
        n++
        // nonce size 24 (ub: without 0 padding, decryption error occurs with a 50% chance)
        val nonce = UByteArray(16) + n.toUByteArray()
        k = config.hash.hash(k)
        println("CipherState > ratchet - n: $n / $nonce (${nonce.size}), key: ${k[0]}-${k[k.size - 1]} (${k.size})")
        return nonce
    }

    fun encrypt(plaintext: UByteArray): UByteArray {
        if (mode == CipherStateMode.RX) throw IllegalCryptoOperation(mode)
        val nonce = ratchet()
        return config.cipher.encrypt(plaintext, AD, nonce, k.copyOf(32))
    }

    fun decrypt(ciphertextAndTag: UByteArray): UByteArray {
        if (mode == CipherStateMode.TX) throw IllegalCryptoOperation(mode)
        val nonce = ratchet()
        return config.cipher.decrypt(ciphertextAndTag, AD, nonce, k.copyOf(32))
    }
}
