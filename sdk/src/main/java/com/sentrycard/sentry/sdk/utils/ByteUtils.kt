package com.sentrycard.sentry.sdk.utils

import com.sun.jna.Memory
import java.util.Locale


fun ByteArray.formatted(): String =
    byteArrayToHexString(this).chunked(2).joinToString(" ")

fun intToByteArray(vararg elements: Int): ByteArray =
    elements
        .map { it.toByte() }
        .toByteArray()

fun ByteArray.byteArrayToHexString(data: ByteArray?): String {
    return if (data == null) {
        ""
    } else {
        val hexString = StringBuffer(data.size * 2)
        for (i in data.indices) {
            val currentByte = data[i].toInt() and 255
            if (currentByte < 16) {
                hexString.append('0')
            }
            hexString.append(Integer.toHexString(currentByte))
        }
        hexString.toString().uppercase(Locale.getDefault())
    }
}

fun ByteArray.asPointer() = Memory(size.toLong()).apply {
    forEachIndexed { index, i ->
        setByte(index.toLong(), i.toByte())
    }
}