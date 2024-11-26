package com.sentrycard.sentry.sdk.models

/**
Contains internal data necessary to initiate communication with the card over a secure channel.
 */
data class AuthInitData(
    val apduCommand: ByteArray,
    val privateKey: ByteArray,
    val publicKey: ByteArray,
    val sharedSecret: ByteArray,
)

/**
Security Keys.
 */
data class Keys(
    val keyRespt: ByteArray,
    val keyENC: ByteArray,
    val keyCMAC: ByteArray,
    val keyRMAC: ByteArray,
    val chainingValue: ByteArray,
)