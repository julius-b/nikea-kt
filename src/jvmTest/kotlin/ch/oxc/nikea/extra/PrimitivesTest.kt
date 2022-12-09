package ch.oxc.nikea.extra

import ch.oxc.nikea.initCrypto
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.util.*
import kotlin.test.assertContentEquals

@OptIn(ExperimentalUnsignedTypes::class)
class PrimitivesTest {
    companion object {
        @JvmStatic
        @BeforeAll
        fun setUp(): Unit = runBlocking {
            initCrypto()
        }
    }

    @Test
    fun testArgon2id() {
        // derive new key
        val derived = Argon2id.derive("Hello World")

        val lastIdx = derived.lastIndexOf('$')
        val derivedKey = Base64.getDecoder().decode(derived.substring(lastIdx + 1)).toUByteArray()

        // validate key using args
        val recoveredKey = Argon2id.derive("Hello World", derived.substring(0, lastIdx))

        assertContentEquals(derivedKey, recoveredKey)
    }
}
