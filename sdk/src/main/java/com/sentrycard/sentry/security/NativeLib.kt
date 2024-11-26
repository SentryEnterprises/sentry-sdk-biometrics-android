package com.sentrycard.sentry.security

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer

@Suppress("FunctionName")
interface NativeLib : Library {


    fun LibAuthWrap(apdu_in: Pointer?, in_len: Int, apdu_out: Pointer?, out_len: Pointer?, key_enc: Pointer?, key_cmac: Pointer?, chaining_value: Pointer?, encryption_counter: Pointer?): Int;
    fun LibAuthUnwrap(apdu_in: Pointer?, in_len: Int, apdu_out: Pointer?, out_len: Pointer?, key_enc: Pointer?, key_rmac: Pointer?, chaining_value: Pointer?, encryption_counter: Pointer?): Int;

    fun LibSecureChannelInit(
        apduCommand: Pointer,
        apduCommandLen: Pointer,
        privateKey: Pointer,
        publicKey: Pointer,
        secretShses: Pointer,
    ): Int

    fun LibCalcSecretKeys(
        pubKey: Pointer,
        shses: Pointer,
        privatekey: Pointer,
        keyRespt: Pointer,
        keyENC: Pointer,
        keyCMAC: Pointer,
        keyRMAC: Pointer,
        chaining: Pointer,
    ): Int

    companion object {
        val INSTANCE: NativeLib = Native.load("libsentrysecurity", NativeLib::class.java)
    }
}