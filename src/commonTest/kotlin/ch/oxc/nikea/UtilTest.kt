package ch.oxc.nikea

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals

class UtilTest {
    @Test
    fun testToUByteArray() = runTest {
        val zero = 0UL
        assertContentEquals(ubyteArrayOf(0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u), zero.toUByteArray())
        val one = 1UL
        assertContentEquals(ubyteArrayOf(0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u), one.toUByteArray())
        val onebyte = 255UL
        assertContentEquals(ubyteArrayOf(0u, 0u, 0u, 0u, 0u, 0u, 0u, 255u), onebyte.toUByteArray())
        val onebyteplusone = 256UL
        assertContentEquals(ubyteArrayOf(0u, 0u, 0u, 0u, 0u, 0u, 1u, 0u), onebyteplusone.toUByteArray())
        val maxvalue = ULong.MAX_VALUE
        assertContentEquals(ubyteArrayOf(255u, 255u, 255u, 255u, 255u, 255u, 255u, 255u), maxvalue.toUByteArray())
    }
}
