@file:OptIn(ExperimentalCoroutinesApi::class, ExperimentalUnsignedTypes::class)

package ch.oxc.nikea

import com.ionspin.kotlin.crypto.scalarmult.ScalarMultiplication
import com.ionspin.kotlin.crypto.signature.Signature
import com.ionspin.kotlin.crypto.util.hexStringToUByteArray
import com.ionspin.kotlin.crypto.util.toHexString
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class HandshakeTest {

    @BeforeTest
    fun setUp() = runBlocking {
        initCrypto()
    }

    @Test
    fun testOpenHandshake() = runTest {
        val bobIdentKey = Ed25519Signature.genKeyPair()
        val bobStatic = X25519DH.genKeyPair()
        val bobEphemeral = X25519DH.genKeyPair()

        val aliceIdentKey = Ed25519Signature.genKeyPair()
        val aliceStatic = X25519DH.genKeyPair()
        val aliceEphemeral = X25519DH.genKeyPair()

        val bobKeys = Keys(
            s = KeyPair(bobStatic.seck, bobStatic.pubk),
            e = KeyPair(bobEphemeral.seck, bobEphemeral.pubk),
            rs = aliceStatic.pubk,
            re = aliceEphemeral.pubk,
            remoteIdentity = Identity(
                pubk = aliceIdentKey.pubk,
                ssig = Ed25519Signature.sign(aliceStatic.pubk, aliceIdentKey.seck),
                esig = Ed25519Signature.sign(aliceEphemeral.pubk, aliceIdentKey.seck)
            )
        )

        val aliceKeys = Keys(
            s = KeyPair(aliceStatic.seck, aliceStatic.pubk),
            e = KeyPair(aliceEphemeral.seck, aliceEphemeral.pubk),
            rs = bobStatic.pubk,
            re = bobEphemeral.pubk,
            remoteIdentity = Identity(
                pubk = bobIdentKey.pubk,
                ssig = Ed25519Signature.sign(bobStatic.pubk, bobIdentKey.seck),
                esig = Ed25519Signature.sign(bobEphemeral.pubk, bobIdentKey.seck)
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
                ssig = Ed25519Signature.sign(aliceStatic.pubk, aliceIdentKey.secretKey),
                esig = Ed25519Signature.sign(aliceEphemeral.pubk, aliceIdentKey.secretKey)
            )
        )

        val aliceKeys = Keys(
            s = KeyPair(aliceStatic.seck, aliceStatic.pubk),
            e = KeyPair(aliceEphemeral.seck, aliceEphemeral.pubk),
            rs = bobStatic.pubk,
            re = bobEphemeral.pubk,
            remoteIdentity = Identity(
                pubk = bobIdentKey.publicKey,
                ssig = Ed25519Signature.sign(bobStatic.pubk, bobIdentKey.secretKey),
                esig = Ed25519Signature.sign(bobEphemeral.pubk, bobIdentKey.secretKey)
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
        val correctIdentity = Ed25519Signature.genKeyPair()
        val badIdentity = Ed25519Signature.genKeyPair()

        val static = X25519DH.genKeyPair()
        val ephemeral = X25519DH.genKeyPair()

        val hs = Handshake()
        val exE = assertFailsWith<InvalidRemoteSignatureException>("expect bad signature to fail") {
            hs.verifyRemoteSignature(
                static.pubk, ephemeral.pubk,
                Identity(
                    correctIdentity.pubk,
                    Ed25519Signature.sign(static.pubk, correctIdentity.seck),
                    Ed25519Signature.sign(ephemeral.pubk, badIdentity.seck)
                )
            )
        }
        assertEquals("Signature validation failed for key: e", exE.message)

        val exS = assertFailsWith<InvalidRemoteSignatureException>("expect bad signature to fail") {
            hs.verifyRemoteSignature(
                static.pubk, ephemeral.pubk,
                Identity(
                    correctIdentity.pubk,
                    Ed25519Signature.sign(static.pubk, badIdentity.seck),
                    Ed25519Signature.sign(ephemeral.pubk, correctIdentity.seck)
                )
            )
        }
        assertEquals("Signature validation failed for key: s", exS.message)
    }
}
