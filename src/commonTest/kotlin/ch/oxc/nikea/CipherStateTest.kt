package ch.oxc.nikea

import com.ionspin.kotlin.crypto.aead.AeadCorrupedOrTamperedDataException
import com.ionspin.kotlin.crypto.util.LibsodiumRandom
import com.ionspin.kotlin.crypto.util.encodeToUByteArray
import com.ionspin.kotlin.crypto.util.hexStringToUByteArray
import com.ionspin.kotlin.crypto.util.toHexString
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class CipherStateTest {
    @BeforeTest
    fun setUp() = runBlocking {
        initCrypto()
    }

    // returns SessionKeys for Alice & Bob
    private fun genSessionKeys(sharedSecretAliceEnc: UByteArray? = null, sharedSecretBobEnc: UByteArray? = null): Pair<SessionKeys, SessionKeys> {
        val sharedSecretAliceEnc = sharedSecretAliceEnc ?: LibsodiumRandom.buf(DefaultConfig.hash.size)
        val sharedSecretBobEnc = sharedSecretBobEnc ?: LibsodiumRandom.buf(DefaultConfig.hash.size)

        val aliceSK = SessionKeys(
            // alice.rx uses bobEnc (bob.tx)
            CipherState(DefaultConfig, CipherStateMode.RX, sharedSecretBobEnc),
            CipherState(DefaultConfig, CipherStateMode.TX, sharedSecretAliceEnc)
        )
        val bobSK = SessionKeys(
            CipherState(DefaultConfig, CipherStateMode.RX, sharedSecretAliceEnc),
            CipherState(DefaultConfig, CipherStateMode.TX, sharedSecretBobEnc)
        )
        return Pair(aliceSK, bobSK)
    }

    @Test
    fun testConst() = runTest {
        val (alice, bob) = genSessionKeys(
            "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111".hexStringToUByteArray(),
            "22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222".hexStringToUByteArray(),
        )

        val bobEnc1 = bob.tx.encrypt("Hello World".encodeToUByteArray())
        assertEquals("991dca71f67f5339a0107ca9863c828ddeaf1adf1a3ecfe69626c8", bobEnc1.toHexString())

        val aliceEnc1 = alice.tx.encrypt("Hello World".encodeToUByteArray())
        assertEquals("7cd82b70e23672efbc63b0217a37d523180f901aa0ae3cda33e924", aliceEnc1.toHexString())
    }

    @Test
    fun testRatchet() = runTest {
        val (alice, bob) = genSessionKeys()

        val bobEnc1 = bob.tx.encrypt("bobEnc1-msg".encodeToUByteArray())
        val aliceDec1 = alice.rx.decrypt(bobEnc1).toByteArray().decodeToString()
        assertEquals("bobEnc1-msg", aliceDec1, "aliceDec1")

        // encryptor & decryptor in sync (encryptor can continue)
        assertEquals(bob.tx.n, alice.rx.n)
        assertContentEquals(bob.tx.k, alice.rx.k)
        // bobEnc ratcheted but aliceEnc didn't (since alice didn't encrypt anything, encryptors aren't in sync)
        assertNotEquals(bob.tx.n, alice.tx.n)
        assertNotEquals(bob.tx.k.contentToString(), alice.tx.k.contentToString())

        val bobEnc2 = bob.tx.encrypt("bobEnc2-msg".encodeToUByteArray())
        val aliceDec2 = alice.rx.decrypt(bobEnc2).toByteArray().decodeToString()
        assertEquals("bobEnc2-msg", aliceDec2, "aliceDec2")

        // encryptor & decryptor in sync (encryptor can continue)
        assertEquals(bob.tx.n, alice.rx.n)
        assertContentEquals(bob.tx.k, alice.rx.k)

        val bobEnc3 = bob.tx.encrypt("bobEnc3-msg".encodeToUByteArray())

        // without decrypting first, aliceEnc is now out of sync, but aliceDec is still in sync with bob
        val aliceEnc1 = alice.tx.encrypt("aliceEnc1-msg".encodeToUByteArray())

        val aliceDec3 = alice.rx.decrypt(bobEnc3).toByteArray().decodeToString()
        assertEquals("bobEnc3-msg", aliceDec3, "aliceDec3")

        val bobDec1 = bob.rx.decrypt(aliceEnc1).toByteArray().decodeToString()
        assertEquals("aliceEnc1-msg", bobDec1, "bobDec1")

        // both in sync
        assertEquals(bob.tx.n, alice.rx.n)
        assertContentEquals(bob.tx.k, alice.rx.k)
        // not in sync anymore (good)
        assertNotEquals(bob.tx.n, alice.tx.n)
        assertNotEquals(bob.tx.k.contentToString(), alice.tx.k.contentToString())
    }

    @Test
    fun testIllegalDecrypt() {
        val (alice, _) = genSessionKeys()

        val exRx =
            assertFailsWith<IllegalCryptoOperation>("rx could encrypt?") { alice.rx.encrypt("rx can't encrypt".encodeToUByteArray()) }
        assertEquals("Operation not allowed with mode: RX", exRx.message)
        val exTx =
            assertFailsWith<IllegalCryptoOperation>("tx could decrypt?") { alice.tx.decrypt("tx can't decrypt".encodeToUByteArray()) }
        assertEquals("Operation not allowed with mode: TX", exTx.message)
    }

    @Test
    fun testBadDecrypt() {
        val (_, bob) = genSessionKeys()

        // NegativeArraySizeException: -16: likely auth tag is taken (can't test: java.lang exceptions not available in common)
        //assertFailsWith<> { alice.rx.decrypt(UByteArray(0)) }

        assertFailsWith<AeadCorrupedOrTamperedDataException>("tag can't be valid") { bob.rx.decrypt(UByteArray(32 + 16) { 0x1U }) }
    }
}
