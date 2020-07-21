package mz

@kotlin.ExperimentalUnsignedTypes
fun ByteArray.getUIntAt(idx: Int, isForeignByteOrder: Boolean): UInt =
   if (isForeignByteOrder)
        ((this[idx+3].toUInt() and 0xFFu) shl 24) or
        ((this[idx+2].toUInt() and 0xFFu) shl 16) or
        ((this[idx+1].toUInt() and 0xFFu) shl 8)  or
         (this[idx  ].toUInt() and 0xFFu)
   else ((this[idx  ].toUInt() and 0xFFu) shl 24) or
        ((this[idx+1].toUInt() and 0xFFu) shl 16) or
        ((this[idx+2].toUInt() and 0xFFu) shl 8)  or
         (this[idx+3].toUInt() and 0xFFu)

@kotlin.ExperimentalUnsignedTypes
fun ByteArray.toHexString() = asUByteArray().joinToString("") { it.toString(16).padStart(2, '0') }

fun bytes(vararg ints: Int) = ByteArray(ints.size) { pos -> ints[pos].toByte() }
