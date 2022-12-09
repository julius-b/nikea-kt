@file:OptIn(ExperimentalUnsignedTypes::class)

package ch.oxc.nikea

import com.ionspin.kotlin.crypto.LibsodiumInitializer
import com.ionspin.kotlin.crypto.keyexchange.KeyExchange
import com.ionspin.kotlin.crypto.signature.InvalidSignatureException
import com.ionspin.kotlin.crypto.signature.Signature
import com.ionspin.kotlin.crypto.util.encodeToUByteArray
import com.ionspin.kotlin.crypto.util.toHexString

data class Config(
    val sig: SignatureAlgo,
    //val dh: DHAlgo,
    val cipher: CipherAlgo,
    // hash ratchet
    val hash: HashAlgo
)

val DefaultConfig = Config(Ed25519Signature, XChaCha20Poly1305Cipher, HashAlgo.SHA512)

data class KeyPair(
    val seck: UByteArray,
    val pubk: UByteArray
)

data class Keys(
    // The local party's static key pair
    val s: KeyPair,
    // The local party's ephemeral key pair
    val e: KeyPair,
    // The remote party's static public key
    val rs: UByteArray,
    // The remote party's ephemeral public key
    val re: UByteArray,
    // Signed keys of remote party
    val remoteIdentity: Identity
)

// Identity provides key authentication
data class Identity(
    val pubk: UByteArray,
    // static public key signature
    val ssig: UByteArray,
    // ephemeral public key signature
    val esig: UByteArray
)

suspend fun initCrypto() {
    if (!LibsodiumInitializer.isInitialized()) LibsodiumInitializer.initialize()
}

class InvalidRemoteSignatureException(key: Char) : RuntimeException("Signature validation failed for key: $key")

data class SessionKeys(
    val rx: CipherState,
    val tx: CipherState
)

class Handshake(private val config: Config = DefaultConfig) {

    // open handshake as initializer
    // returns encryptState, decryptState
    fun initiate(keys: Keys): SessionKeys {
        verifyRemoteSignature(keys.rs, keys.re, keys.remoteIdentity)
        // initiator: s, e
        // pattern `es`: initiator ephemeral & responder static

        // doc: `rx || tx = BLAKE2B-512(p.n || client_pk || server_pk)`
        // rx & tx are the blake 64B split in 2x 32B
        val dhes = KeyExchange.clientSessionKeys(keys.e.pubk, keys.e.seck, keys.rs)
        val dhss = KeyExchange.clientSessionKeys(keys.s.pubk, keys.s.seck, keys.rs)
        val dhee = KeyExchange.clientSessionKeys(keys.e.pubk, keys.e.seck, keys.re)
        val dhse = KeyExchange.clientSessionKeys(keys.s.pubk, keys.s.seck, keys.re)

        // outdated Libsodium api: `scalarMultiplication` (KeyExchange api already adds both public keys to the hash)
        // `scalarMultiplication` (and protocols such as Noise & Briar) recommend adding both public keys to the hash
        //val h = config.hash.hash(SHARED_SECRET.encodeToUByteArray() + keys.e.pubk + keys.re + dhes + dhss + dhee + dhse + keys.s.pubk + keys.rs)

        // save context + intention in hash
        val decH =
            config.hash.hash(SHARED_SECRET.encodeToUByteArray() + dhes.receiveKey + dhss.receiveKey + dhee.receiveKey + dhse.receiveKey)
        val encH =
            config.hash.hash(SHARED_SECRET.encodeToUByteArray() + dhes.sendKey + dhss.sendKey + dhee.sendKey + dhse.sendKey)
        return SessionKeys(CipherState(config, CipherStateMode.RX, decH), CipherState(config, CipherStateMode.TX, encH))
    }

    // open handshake as responder
    fun respond(keys: Keys): SessionKeys {
        verifyRemoteSignature(keys.rs, keys.re, keys.remoteIdentity)
        // initiator: rs, re
        val dhes = KeyExchange.serverSessionKeys(keys.s.pubk, keys.s.seck, keys.re)
        val dhss = KeyExchange.serverSessionKeys(keys.s.pubk, keys.s.seck, keys.rs)
        val dhee = KeyExchange.serverSessionKeys(keys.e.pubk, keys.e.seck, keys.re)
        val dhse = KeyExchange.serverSessionKeys(keys.e.pubk, keys.e.seck, keys.rs)

        //val h = config.hash.hash(SHARED_SECRET.encodeToUByteArray() + keys.re + keys.e.pubk + dhes + dhss + dhee + dhse + keys.rs + keys.s.pubk)

        val decH =
            config.hash.hash(SHARED_SECRET.encodeToUByteArray() + dhes.receiveKey + dhss.receiveKey + dhee.receiveKey + dhse.receiveKey)
        val encH =
            config.hash.hash(SHARED_SECRET.encodeToUByteArray() + dhes.sendKey + dhss.sendKey + dhee.sendKey + dhse.sendKey)
        return SessionKeys(CipherState(config, CipherStateMode.RX, decH), CipherState(config, CipherStateMode.TX, encH))
    }

    fun verifyRemoteSignature(rs: UByteArray, re: UByteArray, remoteIdentity: Identity) {
        if (!config.sig.verify(remoteIdentity.ssig, rs, remoteIdentity.pubk))
            throw InvalidRemoteSignatureException('s')

        if (!config.sig.verify(remoteIdentity.esig, re, remoteIdentity.pubk))
            throw InvalidRemoteSignatureException('e')
    }
}
