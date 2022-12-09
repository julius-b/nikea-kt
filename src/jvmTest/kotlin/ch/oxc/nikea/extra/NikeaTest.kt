package ch.oxc.nikea.extra

import ch.oxc.nikea.initCrypto
import com.ionspin.kotlin.crypto.keyexchange.KeyExchange
import com.ionspin.kotlin.crypto.util.LibsodiumRandom
import com.ionspin.kotlin.crypto.util.encodeToUByteArray
import com.ionspin.kotlin.crypto.util.hexStringToUByteArray
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNotEquals

@OptIn(ExperimentalCoroutinesApi::class, ExperimentalUnsignedTypes::class)
class NikeaTest {

    companion object {
        @JvmStatic
        @BeforeAll
        fun setUp(): Unit = runBlocking {
            initCrypto()
        }
    }

    @Test
    fun testVaultKey() = runTest {
        val password = "Secret"
        val ad = "verify this".encodeToUByteArray()
        val newVK = VaultKey.new(
            password, ad, kekNonce = "111111111111111111111111111111111111111111111111".hexStringToUByteArray()
        )
        println("vaultKey: $newVK, seckClr: #${newVK.seckClr.size}, seckEnc: #${newVK.seckEnc.size}")

        val recoveredVK = VaultKey.recover(password, newVK.args, newVK.seckEnc, ad)
        println("recoveredVK: $recoveredVK}")

        assertContentEquals(newVK.seckClr, recoveredVK.seckClr, "seckClr")
        assertContentEquals(newVK.seckEnc, recoveredVK.seckEnc, "seckEnc")
    }

    @Test
    fun testIdentityKey() = runTest {
        val identityKey = IdentityKey.new()

        assertTrue(identityKey.algo.signer.verify(identityKey.pubkSigned, identityKey.keys.pubk, identityKey.keys.pubk))
        assertFalse(
            identityKey.algo.signer.verify(
                LibsodiumRandom.buf(64),
                identityKey.keys.pubk,
                identityKey.keys.pubk
            )
        )
    }

    @Test
    fun testKexKey() = runTest {
        val identityKey1 = IdentityKey.new()
        val identityKey2 = IdentityKey.new()
        val kexKey1 = KexKey.new(identityKey1.keys.seck)
        val kexKey2 = KexKey.new(identityKey2.keys.seck)

        val dhClient = KeyExchange.clientSessionKeys(kexKey1.keys.pubk, kexKey1.keys.seck, kexKey2.keys.pubk)
        val dhServer = KeyExchange.serverSessionKeys(kexKey2.keys.pubk, kexKey2.keys.seck, kexKey1.keys.pubk)
        assertContentEquals(dhClient.sendKey, dhServer.receiveKey)
        assertContentEquals(dhClient.receiveKey, dhServer.sendKey)
        assertNotEquals(dhClient.receiveKey.contentToString(), dhServer.receiveKey.contentToString())
        assertNotEquals(dhClient.sendKey.contentToString(), dhServer.sendKey.contentToString())
    }
}
