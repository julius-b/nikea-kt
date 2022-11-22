@file:OptIn(ExperimentalUnsignedTypes::class)

package ch.oxc.nikea

// TODO package name per caller
var SHARED_SECRET = "SHARED_SECRET"

// 2^64-1 (MAX_VALUE) is reserved for rekeys, 2^64-2 can be reached
val MaxNonce = ULong.MAX_VALUE - 1UL

// If you need to use bytes greater than 0x7F, you can use unsigned literals to make a UByteArray and then convert it back into a ByteArray:
//ubyteArrayOf(0xA1U, 0x2EU, 0x38U, 0xD4U, 0x89U, 0xC3U).toByteArray()
fun byteArrayOfInts(vararg ints: Int) = ByteArray(ints.size) { pos -> ints[pos].toByte() }

fun ubyteArrayOfInts(vararg ints: Int) = UByteArray(ints.size) { pos -> ints[pos].toUByte() }

// MSB first (big endian)
// 1 = UByteArray(storage=[0, 0, 0, 0, 0, 0, 0, 1])
fun ULong.toUByteArray(): UByteArray {
    return ubyteArrayOf(
        (this shr 56).toUByte(),
        (this shr 48).toUByte(),
        (this shr 40).toUByte(),
        (this shr 32).toUByte(),
        (this shr 24).toUByte(),
        (this shr 16).toUByte(),
        (this shr 8).toUByte(),
        this.toUByte() // least significant byte
    )
}
