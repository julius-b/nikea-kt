@file:OptIn(ExperimentalCoroutinesApi::class, ExperimentalUnsignedTypes::class)

package ch.oxc.nikea

import com.ionspin.kotlin.crypto.keyexchange.KeyExchange
import com.ionspin.kotlin.crypto.scalarmult.ScalarMultiplication
import com.ionspin.kotlin.crypto.scalarmult.crypto_scalarmult_BYTES
import com.ionspin.kotlin.crypto.scalarmult.crypto_scalarmult_SCALARBYTES
import com.ionspin.kotlin.crypto.signature.*
import com.ionspin.kotlin.crypto.util.encodeToUByteArray
import com.ionspin.kotlin.crypto.util.hexStringToUByteArray
import com.ionspin.kotlin.crypto.util.toHexString
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlin.test.*

// testing consts can be considered as a 'compatibility test suite', using known values and verifying the results are the same
// since other languages may not have convenient Libsodium bindings, these tests ensure that custom KeyExchange implementations behave the same way
// NOTE: constants were simply selected from known documentation
class PrimitivesTest {

    @BeforeTest
    fun setUp() = runBlocking {
        init()
    }

    @Test
    fun testEd25519Const() = runTest {
        // secretKey: seed||publickey
        val ed25519Seed = "1111111111111111111111111111111111111111111111111111111111111111".hexStringToUByteArray()

        // only for ed25519 keys
        val ed25519Key = Signature.seedKeypair(ed25519Seed)
        assertEquals("d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737", ed25519Key.publicKey.toHexString(), "libsodium seedKeypair")

        val pubkSig = Signature.detached(ed25519Key.publicKey, ed25519Key.secretKey)
        println("pubkSig: ${pubkSig.toHexString()}")
        assertEquals("f25bc1115ba369af4fbab86a4274bbecddd536b53b5ec3ac8e3658aacb5319b879674e74738803d1afac224176ae11a011a17cb07e0c65e99432c2f0b1edc307", pubkSig.toHexString())
    }

    @Test
    fun testX25519Const() = runTest {
        // ubyteArrayOfInts(0x5d, 0xab, 0x08, ...)
        val x25519Seed = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb".hexStringToUByteArray()

        // only for x25519 keys
        val x25519Pubk = ScalarMultiplication.scalarMultiplicationBase(x25519Seed)
        assertEquals("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", x25519Pubk.toHexString(), "libsodium scalarMultiplicationBase")

        val otherX25519Seed = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a".hexStringToUByteArray()
        val otherX25519Pubk = ScalarMultiplication.scalarMultiplicationBase(otherX25519Seed)
        assertEquals("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", otherX25519Pubk.toHexString(), "libsodium scalarMultiplicationBase")

        val sharedSecretA = ScalarMultiplication.scalarMultiplication(x25519Seed, otherX25519Pubk)
        val sharedSecretB = ScalarMultiplication.scalarMultiplication(otherX25519Seed, x25519Pubk)
        assertContentEquals(sharedSecretA, sharedSecretB)
        assertEquals("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", sharedSecretA.toHexString())
    }

    @Test
    fun testXChaChaPoly1305Const() = runTest {
        val aead = CipherAlgo.XCHACHA20_POLY1305

        val key1 = "1111111111111111111111111111111111111111111111111111111111111111".hexStringToUByteArray()
        val key2 = "2222222222222222222222222222222222222222222222222222222222222222".hexStringToUByteArray()
        val nonce = UByteArray(16) + (1UL).toUByteArray()
        println("nonce: $nonce")

        val ciphertext1 = aead.encrypt("Hello World".encodeToUByteArray(), UByteArray(0), nonce, key1)
        assertContentEquals("907917d21ece996ac8ecad83c352805bdca225ae7dfd62412d63c7".hexStringToUByteArray(), ciphertext1)

        val ciphertext2 = aead.encrypt("Hello World".encodeToUByteArray(), UByteArray(0), nonce, key2)
        assertContentEquals("4f18cd2b55da419599694380882c07a7637b61b610c9cdef867ea0".hexStringToUByteArray(), ciphertext2)
    }

    @Test
    fun testKeyExchangeConst() = runTest {
        val x25519Seed = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb".hexStringToUByteArray()
        val x25519Pubk = ScalarMultiplication.scalarMultiplicationBase(x25519Seed)

        val otherX25519Seed = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a".hexStringToUByteArray()
        val otherX25519Pubk = ScalarMultiplication.scalarMultiplicationBase(otherX25519Seed)

        val kexSK = KeyExchange.clientSessionKeys(x25519Pubk, x25519Seed, otherX25519Pubk)
        val otherKexSK = KeyExchange.serverSessionKeys(otherX25519Pubk, otherX25519Seed, x25519Pubk)
        assertContentEquals(kexSK.receiveKey, otherKexSK.sendKey)
        assertContentEquals(kexSK.sendKey, otherKexSK.receiveKey)
        assertNotEquals(kexSK.receiveKey.toHexString(), otherKexSK.receiveKey.toHexString())
        assertNotEquals(kexSK.sendKey.toHexString(), otherKexSK.sendKey.toHexString())

        assertEquals("1ad7d1f6d5270fbb18123f3bc904c7f97283e7d47bbe85606ee5ded0af2608c5", kexSK.receiveKey.toHexString())
        assertEquals("9aede84a8737da34d203e31b6daed56b52c5316a7c9d028621b2717fdaa2d314", kexSK.sendKey.toHexString())
    }

    @Test
    fun testKeySizes() = runTest {
        // since Libsodium calls the methods `scalarMultiplication` without mentioning the algo by name
        assertEquals(64, crypto_sign_BYTES)
        assertEquals(32, crypto_sign_SEEDBYTES)
        assertEquals(32, crypto_sign_PUBLICKEYBYTES)
        assertEquals(64, crypto_sign_SECRETKEYBYTES)

        assertEquals(32, crypto_scalarmult_BYTES)
        assertEquals(32, crypto_scalarmult_SCALARBYTES)
    }
}
