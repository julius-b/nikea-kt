@file:OptIn(ExperimentalCoroutinesApi::class, ExperimentalUnsignedTypes::class)

package ch.oxc.nikea

import com.ionspin.kotlin.crypto.box.Box
import com.ionspin.kotlin.crypto.scalarmult.ScalarMultiplication
import com.ionspin.kotlin.crypto.signature.Signature
import com.ionspin.kotlin.crypto.signature.crypto_sign_SEEDBYTES
import com.ionspin.kotlin.crypto.util.LibsodiumRandom
import com.ionspin.kotlin.crypto.util.hexStringToUByteArray
import com.ionspin.kotlin.crypto.util.toHexString
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class HandshakeTest {

    @BeforeTest
    fun setUp() = runBlocking {
        init()
    }

    @Test
    fun testOpenHandshake() = runTest {
        val bobIdentKey = Signature.keypair()
        val bobStatic = Box.keypair()
        val bobEphemeral = Box.keypair()

        val aliceIdentKey = Signature.seedKeypair(LibsodiumRandom.buf(crypto_sign_SEEDBYTES))
        val aliceStatic = Box.keypair()
        val aliceEphemeral = Box.keypair()

        val bobKeys = Keys(
            s = KeyPair(bobStatic.secretKey, bobStatic.publicKey),
            e = KeyPair(bobEphemeral.secretKey, bobEphemeral.publicKey),
            rs = aliceStatic.publicKey,
            re = aliceEphemeral.publicKey,
            remoteIdentity = Identity(
                pubk = aliceIdentKey.publicKey,
                ssig = Signature.detached(aliceStatic.publicKey, aliceIdentKey.secretKey),
                esig = Signature.detached(aliceEphemeral.publicKey, aliceIdentKey.secretKey)
            )
        )

        val aliceKeys = Keys(
            s = KeyPair(aliceStatic.secretKey, aliceStatic.publicKey),
            e = KeyPair(aliceEphemeral.secretKey, aliceEphemeral.publicKey),
            rs = bobStatic.publicKey,
            re = bobEphemeral.publicKey,
            remoteIdentity = Identity(
                pubk = bobIdentKey.publicKey,
                ssig = Signature.detached(bobStatic.publicKey, bobIdentKey.secretKey),
                esig = Signature.detached(bobEphemeral.publicKey, bobIdentKey.secretKey)
            )
        )

        val bobHs = Handshake()
        val (bobDec, bobEnc) = bobHs.initiate(bobKeys)
        val aliceHs = Handshake()
        val (aliceDec, aliceEnc) = aliceHs.respond(aliceKeys)

        assertNotEquals(bobEnc.k.contentToString(), aliceEnc.k.contentToString(), "different chains for send and receive")
        assertNotEquals(aliceDec.k.contentToString(), bobDec.k.contentToString(), "different chains for send and receive")
        assertContentEquals(bobEnc.k, aliceDec.k, "decryptor can decrypt encryptor ciphertext")
        assertContentEquals(aliceEnc.k, bobDec.k, "decryptor can decrypt encryptor ciphertext")
    }

    @Test
    fun testHandshakeConst() = runTest {
        val bobIdentSeed = "1111111111111111111111111111111111111111111111111111111111111111".hexStringToUByteArray()
        val bobIdentKey = Signature.seedKeypair(bobIdentSeed)
        val bobStaticSeed = "3333333333333333333333333333333333333333333333333333333333333333".hexStringToUByteArray()
        val bobStatic = KeyPair(bobStaticSeed, ScalarMultiplication.scalarMultiplicationBase(bobStaticSeed))
        val bobEphemeralSeed = "4444444444444444444444444444444444444444444444444444444444444444".hexStringToUByteArray()
        val bobEphemeral = KeyPair(bobEphemeralSeed, ScalarMultiplication.scalarMultiplicationBase(bobEphemeralSeed))

        val aliceIdentSeed = "2222222222222222222222222222222222222222222222222222222222222222".hexStringToUByteArray()
        val aliceIdentKey = Signature.seedKeypair(aliceIdentSeed)
        val aliceStaticSeed = "5555555555555555555555555555555555555555555555555555555555555555".hexStringToUByteArray()
        val aliceStatic = KeyPair(aliceStaticSeed, ScalarMultiplication.scalarMultiplicationBase(aliceStaticSeed))
        val aliceEphemeralSeed = "6666666666666666666666666666666666666666666666666666666666666666".hexStringToUByteArray()
        val aliceEphemeral = KeyPair(aliceEphemeralSeed, ScalarMultiplication.scalarMultiplicationBase(aliceEphemeralSeed))

        val bobKeys = Keys(
            s = KeyPair(bobStatic.seck, bobStatic.pubk),
            e = KeyPair(bobEphemeral.seck, bobEphemeral.pubk),
            rs = aliceStatic.pubk,
            re = aliceEphemeral.pubk,
            remoteIdentity = Identity(
                pubk = aliceIdentKey.publicKey,
                ssig = Signature.detached(aliceStatic.pubk, aliceIdentKey.secretKey),
                esig = Signature.detached(aliceEphemeral.pubk, aliceIdentKey.secretKey)
            )
        )

        val aliceKeys = Keys(
            s = KeyPair(aliceStatic.seck, aliceStatic.pubk),
            e = KeyPair(aliceEphemeral.seck, aliceEphemeral.pubk),
            rs = bobStatic.pubk,
            re = bobEphemeral.pubk,
            remoteIdentity = Identity(
                pubk = bobIdentKey.publicKey,
                ssig = Signature.detached(bobStatic.pubk, bobIdentKey.secretKey),
                esig = Signature.detached(bobEphemeral.pubk, bobIdentKey.secretKey)
            )
        )

        val bobHs = Handshake()
        val (bobDec, bobEnc) = bobHs.initiate(bobKeys)
        val aliceHs = Handshake()
        val (aliceDec, aliceEnc) = aliceHs.respond(aliceKeys)

        assertEquals(
            "c217eb5894bde10b0db38930b87567b51e61d80713826ce418b7a2cbbb0fdebf9093fa29dc745d2e226c631c46293564fa7173a9c418eb642f8a964709e476ac",
            bobDec.k.toHexString()
        )
        assertEquals(
            "15e0e8f39c09208d6a2fcb04402aa197f6398f942386ca88ecc121c60d0c455fed0c8787c0337141eeab83c362c765198efa73787357f39eee459327344213f6",
            bobEnc.k.toHexString()
        )
        assertEquals(
            "15e0e8f39c09208d6a2fcb04402aa197f6398f942386ca88ecc121c60d0c455fed0c8787c0337141eeab83c362c765198efa73787357f39eee459327344213f6",
            aliceDec.k.toHexString()
        )
        assertEquals(
            "c217eb5894bde10b0db38930b87567b51e61d80713826ce418b7a2cbbb0fdebf9093fa29dc745d2e226c631c46293564fa7173a9c418eb642f8a964709e476ac",
            aliceEnc.k.toHexString()
        )
    }

    @Test
    fun testInvalidRemoteSignature() {
        val correctIdentity = Signature.keypair()
        val badIdentity = Signature.keypair()

        val static = Box.keypair()
        val ephemeral = Box.keypair()

        val hs = Handshake()
        val exE = assertFailsWith<InvalidRemoteSignatureException>("expect bad signature to fail") {
            hs.verifyRemoteSignature(
                static.publicKey, ephemeral.publicKey,
                Identity(
                    correctIdentity.publicKey,
                    Signature.detached(static.publicKey, correctIdentity.secretKey),
                    Signature.detached(ephemeral.publicKey, badIdentity.secretKey)
                )
            )
        }
        assertEquals("Signature validation failed for key: e", exE.message)

        val exS = assertFailsWith<InvalidRemoteSignatureException>("expect bad signature to fail") {
            hs.verifyRemoteSignature(
                static.publicKey, ephemeral.publicKey,
                Identity(
                    correctIdentity.publicKey,
                    Signature.detached(static.publicKey, badIdentity.secretKey),
                    Signature.detached(ephemeral.publicKey, correctIdentity.secretKey)
                )
            )
        }
        assertEquals("Signature validation failed for key: s", exS.message)
    }
}
