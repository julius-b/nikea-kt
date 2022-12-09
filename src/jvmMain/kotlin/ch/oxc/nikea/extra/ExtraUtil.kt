package ch.oxc.nikea.extra

import java.util.*

// not kotlin.String
fun ByteArray.toUtf8(): String = String(this, Charsets.UTF_8)

fun ByteArray.toBase64(): String = String(Base64.getEncoder().encode(this))
