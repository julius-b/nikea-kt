@file:OptIn(ExperimentalUnsignedTypes::class)

package ch.oxc.nikea

val AD = UByteArray(0)

enum class CipherStateMode {
    RXTX, RX, TX
}

class IllegalCryptoOperation(mode: CipherStateMode) : RuntimeException("Operation not allowed with mode: $mode")

// individual CipherState for rx/tx:
// - Having different keys for each direction allows counters to be safely used as nonces without having to wait for an acknowledgment after every message.
// - Initiator & Responder need to be able to encrypt & decrypt independently
//   - -> Encrypt without modifying the k/n of the decrypt ratchet
@OptIn(ExperimentalUnsignedTypes::class)
class CipherState(private val config: Config, private val mode: CipherStateMode, var k: UByteArray) {

    init {
        if (k.size != 64) throw IllegalArgumentException("key size: ${k.size}")
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
