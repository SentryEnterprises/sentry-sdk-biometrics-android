package com.sentrycard.sentry.sdk.biometrics


import android.nfc.Tag
import android.nfc.tech.IsoDep
import com.sentrycard.sentry.security.NativeLib
import com.sentrycard.sentry.sdk.apdu.APDUCommand
import com.sentrycard.sentry.sdk.presentation.SentrySDKError
import com.sentrycard.sentry.sdk.apdu.APDUResponseCode
import com.sentrycard.sentry.sdk.models.AuthInitData
import com.sentrycard.sentry.sdk.models.BiometricEnrollmentStatus
import com.sentrycard.sentry.sdk.models.BiometricMode
import com.sentrycard.sentry.sdk.models.FingerTouches
import com.sentrycard.sentry.sdk.models.FingerprintValidation
import com.sentrycard.sentry.sdk.models.FingerprintValidationAndData
import com.sentrycard.sentry.sdk.models.Keys
import com.sentrycard.sentry.sdk.models.NfcActionResult
import com.sentrycard.sentry.sdk.models.VersionInfo
import com.sentrycard.sentry.sdk.utils.asPointer
import com.sentrycard.sentry.sdk.utils.formatted
import com.sun.jna.Memory
import com.sun.jna.Pointer
import java.nio.ByteBuffer
import kotlin.Int


private data class APDUReturnResult(val data: ByteArray, val statusWord: Int)

private const val SUCCESS = 0

private const val ERROR_KEYGENERATION = -100
private const val ERROR_SHAREDSECRETEXTRACTION = -101

enum class DataSlot {
    Small,
    Huge
}

/**
Communicates with the IDEX Enroll applet by sending various `APDU` commands in the appropriate order.
 */
internal class BiometricsApi(
    val isDebugOutputVerbose: Boolean = true,
) {

    // Note - This is reset when selecting a new applet (i.e. after initing the secure channel)
    private var encryptionCounter: ByteArray = ByteArray(16) { 0 }

    // Note - this changes with every wrap, and resets when initing secure channel
    private var chainingValue: ByteArray = ByteArray(16) { 0 }


    private var privateKey: ByteArray = byteArrayOf()
    private var publicKey: ByteArray = byteArrayOf()
    private var sharedSecret: ByteArray = byteArrayOf()
    private var keyRespt: ByteArray = byteArrayOf()
    private var keyENC: ByteArray = byteArrayOf()
    private var keyCMAC: ByteArray = byteArrayOf()
    private var keyRMAC: ByteArray = byteArrayOf()

    data class WrapAPDUCommandResponse(
        val encryptionCounter: ByteArray,
        val chainingValue: ByteArray,
        val wrapped: ByteArray
    )

    private fun wrapAPDUCommand(
        apduCommand: ByteArray,
        keyEnc: ByteArray,
        keyCmac: ByteArray,
        chainingValue: ByteArray,
        encryptionCounter: ByteArray
    ): WrapAPDUCommandResponse {

        log("calcSecretKeys encryptionCounter ${encryptionCounter.formatted()} ")

        val command = apduCommand.asPointer()
        val wrappedCommand = Memory(300)
        val enc = keyEnc.asPointer()
        val cmac = keyCmac.asPointer()
        val chaining = chainingValue.asPointer()
        val counter = encryptionCounter.asPointer()
        val wrappedLength = Memory(1)

        val response = NativeLib.INSTANCE.LibAuthWrap(
            command,
            apduCommand.size,
            wrappedCommand,
            wrappedLength,
            enc,
            cmac,
            chaining,
            counter
        )


        if (response != SUCCESS) {
            if (response == ERROR_KEYGENERATION) {
                throw SentrySDKError.KeyGenerationError
            }
            if (response == ERROR_SHAREDSECRETEXTRACTION) {
                throw SentrySDKError.SharedSecretExtractionError
            }

            // TODO: Fix once we've converted security to pure Swift
            error("Unknown return value $response")
        }

        counter.getByteArray(0, 16).copyInto(encryptionCounter)
        chaining.getByteArray(0, 16).copyInto(chainingValue)

        return WrapAPDUCommandResponse(
            encryptionCounter = counter.getByteArray(0, encryptionCounter.size),
            chainingValue = chaining.getByteArray(0, chainingValue.size),
            wrapped = wrappedCommand.getByteArray(0, wrappedLength.getByte(0).toInt())
        )
    }

    /**
     * Retrieves the biometric enrollment status recorded by the Enrollment applet on the card.
     *
     * @param tag The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     * @return BiometricEnrollmentStatus structure containing information on the fingerprint enrollment status.
     *
     * This method can throw the following exceptions:
     * `SentrySDKError.enrollmentStatusBufferTooSmall` if the buffer returned from the `APDU` command was unexpectedly too small.
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.

     */
    fun getEnrollmentStatus(tag: Tag): BiometricEnrollmentStatus {
        log("----- BiometricsAPI Get Enrollment Status")
        var dataArray: ByteArray = byteArrayOf()

        log("     Getting enrollment status")

        val enrollStatusCommand = wrapAPDUCommand(
            apduCommand = APDUCommand.GET_ENROLL_STATUS.value,
            keyEnc = keyENC,
            keyCmac = keyCMAC,
            chainingValue = chainingValue,
            encryptionCounter = encryptionCounter
        )
        val returnData =
            send(
                apduCommand = enrollStatusCommand.wrapped,
                name = "Get Enroll Status",
                tag = tag
            )

        if (returnData.statusWord != APDUResponseCode.OPERATION_SUCCESSFUL.value) {
            throw SentrySDKError.ApduCommandError(returnData.statusWord)
        }

        dataArray = unwrapAPDUResponse(
            response = returnData.data,
            statusWord = returnData.statusWord,
            chainingValue = chainingValue,
            encryptionCounter = encryptionCounter
        )


        // sanity check - this buffer should be at least 40 bytes in length, possibly more
        if (dataArray.size < 40) {
            throw SentrySDKError.EnrollmentStatusBufferTooSmall
        }

        // if we're dealing with Enroll app prior to 2.1
        if (dataArray[0] == 0x00.toByte()) {
            // extract values from specific index in the array
            val maxNumberOfFingers = dataArray[31].toInt()
            val enrolledTouches = dataArray[32].toInt()
            val remainingTouches = dataArray[33].toInt()
            val mode = dataArray[39]

            log("     # Fingers: $maxNumberOfFingers)\n     Enrolled Touches: $enrolledTouches\n     Remaining Touches: $remainingTouches\n     Mode: $mode")

            val biometricMode: BiometricMode =
                if (mode == 0x00.toByte()) BiometricMode.Enrollment else BiometricMode.Verification

            log("------------------------------\n")

            return BiometricEnrollmentStatus(
                version = 0,
                maximumFingers = maxNumberOfFingers,
                enrollmentByFinger = listOf(
                    FingerTouches(
                        enrolledTouches = enrolledTouches,
                        remainingTouches = remainingTouches,
                        biometricMode = null
                    )
                ),
                nextFingerToEnroll = 1,
                mode = biometricMode
            )
        } else if (dataArray[0] == 0x01.toByte()) {
            val maxNumberOfFingers = dataArray[31].toInt()
            val finger1EnrolledTouches = dataArray[32].toInt()
            val finger1RemainingTouches = dataArray[33].toInt()
            val finger1TopupTouches = dataArray[34].toInt()
            val finger1QualTouches = dataArray[35].toInt()
            val finger1QualPasses = dataArray[36].toInt()
            val finger1BioMode = dataArray[37].toInt()
            val finger1TopupRemaining = dataArray[38].toInt()
            val finger1TopupAttempts = dataArray[39].toInt()
            val finger2EnrolledTouches = dataArray[40].toInt()
            val finger2RemainingTouches = dataArray[41].toInt()
            val finger2TopupTouches = dataArray[42].toInt()
            val finger2QualTouches = dataArray[43].toInt()
            val finger2QualPasses = dataArray[44].toInt()
            val finger2BioMode = dataArray[45].toInt()
            val finger2TopupRemaining = dataArray[46].toInt()
            val finger2TopupAttempts = dataArray[47].toInt()
            val reenrollAttempts = dataArray[48].toInt()
            val nextFingerToEnroll = dataArray[49].toInt()
            val mode = dataArray[50]

            log(
                "     # Fingers: $maxNumberOfFingers\n" +
                        "     F1 Enrolled Touches: $finger1EnrolledTouches\n" +
                        "     F1 Remaining Touches: $finger1RemainingTouches\n" +
                        "     F1 Topup Touches: $finger1TopupTouches\n" +
                        "     F1 Qual Touches: $finger1QualTouches\n" +
                        "     F1 Qual Passed: $finger1QualPasses\n" +
                        "     F1 Biometric Mode: $finger1BioMode\n" +
                        "     F1 Topup Remaining: $finger1TopupRemaining\n" +
                        "     F1 Topup Attempts: $finger1TopupAttempts\n" +
                        "     F2 Enrolled Touches: $finger2EnrolledTouches\n" +
                        "     F2 Remaining Touches: $finger2RemainingTouches\n" +
                        "     F2 Topup Touches: $finger2TopupTouches\n" +
                        "     F2 Qual Touches: $finger2QualTouches\n" +
                        "     F2 Qual Passed: $finger2QualPasses\n" +
                        "     F2 Biometric Mode: $finger2BioMode\n" +
                        "     F2 Topup Remaining: $finger2TopupRemaining\n" +
                        "     F2 Topup Attempts: $finger2TopupAttempts\n" +
                        "     Reenroll Attempts: $reenrollAttempts\n" +
                        "     Next Finger: $nextFingerToEnroll\n" +
                        "     Mode: $mode\n"
            )

            // need to check all fingers
            var biometricMode: BiometricMode = BiometricMode.Enrollment
            if (finger1BioMode > 1 && finger2BioMode > 1) {
                biometricMode = BiometricMode.Verification
            }

            log("------------------------------\n")

            return BiometricEnrollmentStatus(
                version = 1,
                maximumFingers = maxNumberOfFingers,
                enrollmentByFinger = listOf(
                    FingerTouches(
                        enrolledTouches = finger1EnrolledTouches,
                        remainingTouches = finger1RemainingTouches,
                        biometricMode = finger1BioMode
                    ),
                    FingerTouches(
                        enrolledTouches = finger2EnrolledTouches,
                        remainingTouches = finger2RemainingTouches,
                        biometricMode = finger2BioMode
                    )
                ),
                nextFingerToEnroll = nextFingerToEnroll,
                mode = biometricMode
            )

        } else {
            throw SentrySDKError.UnsupportedEnrollAppletVersion(dataArray[0].toInt())
        }

    }

    /**
    Writes data to the indicated data slot on the SentryCard. A biometric verification is performed first before writing the data. The `.small` data slot holds up to 255 bytes of data, and the `.huge` data slot holds up to 2048 bytes of data.

    - Note: The BioVerify applet does not currently support secure communication, so a secure channel is not used.

    - Parameters:
    - tag: The tag supplied by an NFC connection to which `APDU` commands are sent.
    - data: An array of bytes to write to the indicated data slot.
    - dataSlot: The data slot to which the data is written.

    - Returns: `True`if the finger on the sensor matches the fingerprint recorded during enrollment. If there is a successful match, the indicated data is written to the indicated data slot. Otherwise, returns `false`.

    This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.dataSizeNotSupported` if the `data` parameter is larger than 255 bytes in size for the `.small` data slot, or 2048 bytes for the `.huge` data slot.
     * `SentrySDKError.cvmAppletNotAvailable` if the CVM applet was unavailable for some reason.
     * `SentrySDKError.cvmAppletBlocked` if the CVM applet is in a blocked state and can no longer be used.
     * `SentrySDKError.cvmAppletError` if the CVM applet returned an unexpected error code.

     */
    fun setVerifyStoredDataSecure(tag: Tag, data: ByteArray, dataSlot: DataSlot): Boolean {
        log("----- BiometricsAPI Set Verify Stored Data Secure, slot: $dataSlot\n")


        log("     Setting verify stored data Secure\n")
        var command: ByteArray

        when (dataSlot) {
            DataSlot.Small -> command =
                APDUCommand.setVerifyAppletStoredDataSmallSecure(data = data)

            DataSlot.Huge -> command = APDUCommand.setVerifyAppletStoredDataHugeSecure(data = data)
        }

        //let command = try wrapAPDUCommand(apduCommand: APDUCommand.setVerifyAppletStoredData, keyENC: keyENC, keyCMAC: keyCMAC, chainingValue: &chainingValue, encryptionCounter: &encryptionCounter)
        val returnData = sendAndConfirm(
            apduCommand = command,
            name = "Set Verify Stored Data Secure",
            tag = tag
        )

//        if returnData.statusWord != APDUResponseCode.operationSuccessful.rawValue {
//            throw SentrySDKError.apduCommandError(returnData.statusWord)
//        }
//
//        let dataArray = try unwrapAPDUResponse(response: returnData.data.toArrayOfBytes(), statusWord: returnData.statusWord, keyENC: keyENC, keyRMAC: keyRMAC, chainingValue: chainingValue, encryptionCounter: encryptionCounter)

        return if (returnData.data.size == 1) {
            if (returnData.data[0] == 0x00.toByte()) {
                throw SentrySDKError.CvmAppletNotAvailable
            }

            if (returnData.data[0] == 0x01.toByte()) {
                throw SentrySDKError.CvmAppletBlocked
            }

            if (returnData.data[0] == 0xA5.toByte()) {
                log("     Match\n------------------------------\n")
                true
            }

            if (returnData.data[0] == 0x5A.toByte()) {
                log("     No match found\n------------------------------\n")
                false
            }

            throw SentrySDKError.CvmAppletError(returnData.data[0].toInt())
        } else {
            true
        }
    }

    /**
    Retrieves the data stored in the indicated data slot on the SentryCard. A biometric verification is performed first before retrieving the data.

    - Note: The BioVerify applet does not currently support secure communication, so a secure channel is not used.

    - Parameters:
    - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
    - dataSlot: The data slot from which data is retrieved.

    - Returns: A `FingerprintValidationAndData` structure indicating if the finger on the sensor matches the fingerprint recorded during enrollment. If there is a successful match, this structure also contains the data stored in the indicated data slot. The `.small` data slot returns up to 255 bytes of data. The `.huge` data slot returns up to 2048 bytes of data.

    This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.cvmAppletNotAvailable` if the CVM applet was unavailable for some reason.
     * `SentrySDKError.cvmAppletBlocked` if the CVM applet is in a blocked state and can no longer be used.
     * `SentrySDKError.cvmAppletError` if the CVM applet returned an unexpected error code.

     */
    fun getVerifyStoredDataSecure(tag: Tag, dataSlot: DataSlot): FingerprintValidationAndData {
        log("----- BiometricsAPI Get Verify Stored Data Secure, slot: $dataSlot\n")

        log("     Getting verify stored data Secure\n")
        val command = when (dataSlot) {
            DataSlot.Small -> APDUCommand.GET_VERIFY_APPLET_STORED_DATA_SMALL_SECURED
            DataSlot.Huge -> APDUCommand.GET_VERIFY_APPLET_STORED_DATA_HUGE_SECURED
        }.value

        //let command = try wrapAPDUCommand(apduCommand: APDUCommand.getVerifyAppletStoredData, keyENC: keyENC, keyCMAC: keyCMAC, chainingValue: &chainingValue, encryptionCounter: &encryptionCounter)

        val returnData =
            sendAndConfirm(
                apduCommand = command,
                name = "Get Verify Stored Data Secure",
                tag = tag
            )

//        let dataArray = try unwrapAPDUResponse(response: returnData.data.toArrayOfBytes(), statusWord: returnData.statusWord, keyENC: keyENC, keyRMAC: keyRMAC, chainingValue: chainingValue, encryptionCounter: encryptionCounter)

        if (returnData.data.size == 1) {
            if (returnData.data[0] == 0x00.toByte()) {
                throw SentrySDKError.CvmAppletNotAvailable
            }

            if (returnData.data[0] == 0x01.toByte()) {
                throw SentrySDKError.CvmAppletBlocked
            }

            if (returnData.data[0] == 0xA5.toByte()) {
                log("     Match\n------------------------------\n")
                return FingerprintValidationAndData(
                    doesFingerprintMatch = FingerprintValidation.MatchValid,
                    storedData = returnData.data
                )
            }

            if (returnData.data[0] == 0x5A.toByte()) {
                log("     No match found\n------------------------------\n")
                return FingerprintValidationAndData(
                    doesFingerprintMatch = FingerprintValidation.MatchFailed,
                    storedData = byteArrayOf()
                )
            }

            throw SentrySDKError.CvmAppletError(returnData.data[0].toInt())
        } else {
            log("     Match\n------------------------------\n")
            return FingerprintValidationAndData(
                doesFingerprintMatch = FingerprintValidation.MatchValid,
                storedData = returnData.data
            )
        }
    }

    /**
     * Decodes an APDU command response.
     */
    private fun unwrapAPDUResponse(
        response: ByteArray,
        statusWord: Int,
        chainingValue: ByteArray,
        encryptionCounter: ByteArray
    ): ByteArray {
        val responseData = Memory(response.size + 2L).apply {
            response.forEachIndexed { index, i ->
                setByte(index.toLong(), i.toByte())
            }
            setByte(response.size.toLong(), (statusWord shr 8).toByte())
            setByte(response.size + 1L, (statusWord and 0x00FF).toByte())
        }

        log("unwrapAPDUResponse response ${response.formatted()}")
        log(
            "unwrapAPDUResponse responseData ${
                responseData.getByteArray(0, response.size + 2).formatted()
            }"
        )

        val unwrappedResponse = Memory(300)
        val unwrappedLength = Memory(1)

        val response = NativeLib.INSTANCE.LibAuthUnwrap(
            apdu_in = responseData,
            in_len = response.size + 2,
            apdu_out = unwrappedResponse,
            out_len = unwrappedLength,
            key_enc = keyENC.asPointer(),
            key_rmac = keyRMAC.asPointer(),
            chaining_value = chainingValue.asPointer(),
            encryption_counter = encryptionCounter.asPointer()
        )

        if (response != SUCCESS) {
            if (response == ERROR_KEYGENERATION) {
                throw SentrySDKError.KeyGenerationError
            }
            if (response == ERROR_SHAREDSECRETEXTRACTION) {
                throw SentrySDKError.SharedSecretExtractionError
            }

            // TODO: Fix once we've converted security to pure Swift
            error("Unknown return value $response")
        }

        return unwrappedResponse.getByteArray(0, unwrappedLength.getByte(0).toInt())
    }

    /**
     * Initializes the BioVerify applet by selecting the applet on the SentryCard. Call this method before calling other methods in this unit that communicate with the BioVerify applet.
     * The BioVerify applet does not currently support secure communication, so a secure channel is not setup during initialization.
     *
     * @param tag The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     *
     * This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.secureChannelInitializationError` error occurred initializing the secure communication encryption.
     * `SentrySDKError.secureCommunicationNotSupported` the version of the BioVerify applet on the SentryCard does nto support secure communication (highly unlikely).

     */
    fun initializeVerify(tag: Tag) {

        log("----- BiometricsAPI Initialize Verify")
        log("     Selecting Verify Applet")

        APDUCommand.SELECT_VERIFY_APPLET
        sendAndConfirm(
            apduCommand = APDUCommand.SELECT_VERIFY_APPLET.value,
            name = "Select Verify Applet",
            tag = tag
        )
    }

    @OptIn(ExperimentalStdlibApi::class)
    private fun getAuthInitCommand(): AuthInitData {
        val apduCommand: Pointer = Memory(100)
        val apduCommandLen: Pointer = Memory(1)
        val privateKey: Pointer = Memory(32)
        val publicKey: Pointer = Memory(64)
        val secretShses: Pointer = Memory(32)

        log("LibSecureChannelInit")

        val response = NativeLib.INSTANCE.LibSecureChannelInit(
            apduCommand,
            apduCommandLen,
            privateKey,
            publicKey,
            secretShses
        )
        if (response != SUCCESS) {
            if (response == ERROR_KEYGENERATION) {
                throw SentrySDKError.KeyGenerationError
            }
            if (response == ERROR_SHAREDSECRETEXTRACTION) {
                throw SentrySDKError.SharedSecretExtractionError
            }

            // TODO: Fix once we've converted security to pure Swift
            error("Unknown return value $response")
        }

        return AuthInitData(
            apduCommand = apduCommand.getByteArray(0, apduCommandLen.getByte(0).toInt()),
            privateKey = privateKey.getByteArray(0, 32),
            publicKey = publicKey.getByteArray(0, 64),
            sharedSecret = secretShses.getByteArray(0, 32),
        )
    }

    @OptIn(ExperimentalStdlibApi::class)
    private fun calcSecretKeys(
        receivedPubKey: ByteArray,
        sharedSecret: ByteArray,
        privateKey: ByteArray
    ): Keys {

        val keyRespt = Memory(16)
        val keyENC = Memory(16)
        val keyCMAC = Memory(16)
        val keyRMAC = Memory(16)
        val chaining = Memory(16)


        val response = NativeLib.INSTANCE.LibCalcSecretKeys(
            pubKey = receivedPubKey.asPointer(),
            shses = sharedSecret.asPointer(),
            privatekey = privateKey.asPointer(),
            keyRespt = keyRespt,
            keyENC = keyENC,
            keyCMAC = keyCMAC,
            keyRMAC = keyRMAC,
            chaining = chaining
        )

        if (response != SUCCESS) {
            if (response == ERROR_KEYGENERATION) {
                throw SentrySDKError.KeyGenerationError
            }
            if (response == ERROR_SHAREDSECRETEXTRACTION) {
                throw SentrySDKError.SharedSecretExtractionError
            }

            // TODO: Fix once we've converted security to pure Swift
            error("Unknown return value ${response.toByte().toHexString()}")
        }

        log("calcSecretKeys ")

        return Keys(
            keyRespt = keyRespt.getByteArray(0, 16),
            keyENC = keyENC.getByteArray(0, 16).also {
                log("keyEnc ${it.formatted()}")
            },
            keyCMAC = keyCMAC.getByteArray(0, 16),
            keyRMAC = keyRMAC.getByteArray(0, 16),
            chainingValue = chaining.getByteArray(0, 16)
        )
    }

    /**
     * Initializes the Enroll applet by selecting the applet on the SentryCard and verifying the enroll code. If no enroll code is set, this sets the enroll code to the indicated value. Call this method before calling other methods in this unit that communicate with the Enroll applet.
     *
     * @param tag The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     * @param enrollCode An array of `UInt8` bytes containing the enroll code digits. This array must be 4-6 bytes in length, and each byte must be in the range 0-9.
     *
     * This method can throw the following exceptions:
     * `SentrySDKError.enrollCodeLengthOutOfbounds` if the indicated `enrollCode` is less than four (4) characters or more than six (6) characters in length.
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.enrollCodeDigitOutOfBounds` if an enroll code digit is not in the range 0-9.
     * `SentrySDKError.secureChannelInitializationError` error occurred initializing the secure communication encryption.
     * `SentrySDKError.secureCommunicationNotSupported` the version of the Enroll applet on the SentryCard does nto support secure communication (highly unlikely).

     */
    fun initializeEnroll(tag: Tag, enrollCode: ByteArray) {
        log("----- BiometricsAPI Initialize Enroll - Enroll Code: $enrollCode")

        // sanity check - enroll code must be between 4 and 6 characters
        if (enrollCode.size < 4 || enrollCode.size > 6) {
            throw SentrySDKError.EnrollCodeLengthOutOfBounds
        }

        log("     Selecting Enroll Applet")
        sendAndConfirm(
            apduCommand = APDUCommand.SELECT_ENROLL_APPLET.value,
            name = "Select Enroll Applet",
            tag = tag
        )

        // if using a secure channel, setup keys
        log("     Initializing Secure Channel")

        encryptionCounter = ByteArray(16) { 0 }
        chainingValue = byteArrayOf()
        keyRespt = byteArrayOf()
        keyENC = byteArrayOf()
        keyCMAC = byteArrayOf()
        keyRMAC = byteArrayOf()

        // initialize the secure channel. this sets up keys and encryption
        val authInfo = getAuthInitCommand()
        privateKey = authInfo.privateKey
        publicKey = authInfo.publicKey
        sharedSecret = authInfo.sharedSecret

        val securityInitResponse =
            sendAndConfirm(apduCommand = authInfo.apduCommand, name = "Auth Init", tag = tag)

        val secretKeys = calcSecretKeys(
            receivedPubKey = securityInitResponse.data,
            sharedSecret = sharedSecret,
            privateKey = privateKey
        )

        keyRespt = secretKeys.keyRespt
        keyENC = secretKeys.keyENC
        keyCMAC = secretKeys.keyCMAC
        keyRMAC = secretKeys.keyRMAC
        chainingValue = secretKeys.chainingValue

        val enrollCodeCommand = wrapAPDUCommand(
            apduCommand = APDUCommand.verifyEnrollCode(enrollCode),
            keyEnc = secretKeys.keyENC,
            keyCmac = secretKeys.keyCMAC,
            chainingValue = secretKeys.chainingValue,
            encryptionCounter = encryptionCounter
        )
        sendAndConfirm(enrollCodeCommand.wrapped, "Verify Enroll Code", tag = tag)
    }

    /// Sends an APDU command, throwing an exception if that command does not respond with a successful operation value.
    private fun sendAndConfirm(
        apduCommand: ByteArray,
        name: String? = null,
        tag: Tag,
    ): APDUReturnResult {
        val returnData = send(apduCommand = apduCommand, name = name, tag = tag)

        return if (returnData.statusWord == APDUResponseCode.OPERATION_SUCCESSFUL.value) {
            returnData
        } else {
            throw SentrySDKError.ApduCommandError(returnData.statusWord)
        }
    }

    private fun send(
        apduCommand: ByteArray,
        name: String? = null,
        tag: Tag
    ): APDUReturnResult {
        log("     >>> Sending $name => ${(apduCommand.formatted())}\n")

        val result = tag.transceive(apduCommand)

        log("     >>> Received $name => ${(result.formatted())}\n")

        val statusWord =
            ByteBuffer.wrap(
                byteArrayOf(
                    0x00,
                    0x00,
                    result[result.size - 2],
                    result.last()
                )
            ).int

        return APDUReturnResult(
            data = result.copyOf(result.size - 2),
            statusWord = statusWord
        )


    }

    fun resetEnrollAndScanFingerprint(
        tag: Tag,
        fingerIndex: Int
    ): BiometricEnrollmentStatus {
        if (!(1..2).contains(fingerIndex)) {
            throw SentrySDKError.InvalidFingerIndex
        }
        log("----- BiometricsAPI Reset Enroll and Scan Fingerprint")

        val processFingerprintCommand = wrapAPDUCommand(
            apduCommand = APDUCommand.restartEnrollAndProcessFingerprint(fingerIndex.toByte()),
            keyEnc = keyENC,
            keyCmac = keyCMAC,
            chainingValue = chainingValue,
            encryptionCounter = encryptionCounter
        )
        sendAndConfirm(
            apduCommand = processFingerprintCommand.wrapped,
            name = "Reset And Process Fingerprint",
            tag = tag
        )

        log("     Getting enrollment status")
        val enrollmentStatus = getEnrollmentStatus(tag = tag)
        log("     Remaining: ${enrollmentStatus.enrollmentByFinger[fingerIndex - 1].remainingTouches}")
        return enrollmentStatus
    }

    fun enrollScanFingerprint(tag: Tag, fingerIndex: Int): BiometricEnrollmentStatus {
        log("----- BiometricsAPI Enroll Scan Fingerprint fingerIndex:$fingerIndex")

        val processFingerprintCommand = wrapAPDUCommand(
            apduCommand = APDUCommand.processFingerprint(fingerIndex.toByte()),
            keyEnc = keyENC,
            keyCmac = keyCMAC,
            chainingValue = chainingValue,
            encryptionCounter = encryptionCounter
        )
        sendAndConfirm(
            apduCommand = processFingerprintCommand.wrapped,
            name = "Process Fingerprint",
            tag = tag
        )

        log("     Getting enrollment status")
        val enrollmentStatus = getEnrollmentStatus(tag = tag)

        log("     Remaining: ${enrollmentStatus.enrollmentByFinger[fingerIndex - 1].remainingTouches}")
        return getEnrollmentStatus(tag = tag)
    }

    fun verifyEnrolledFingerprint(tag: Tag) {
        log("----- BiometricsAPI Verify Enrolled Fingerprint")

        val verifyEnrollCommand = wrapAPDUCommand(
            apduCommand = APDUCommand.VERIFY_FINGERPRINT_ENROLLMENT.value,
            keyEnc = keyENC,
            keyCmac = keyCMAC,
            chainingValue = chainingValue,
            encryptionCounter = encryptionCounter
        )
        sendAndConfirm(
            apduCommand = verifyEnrollCommand.wrapped,
            name = "Verify Enrolled Fingerprint",
            tag = tag
        )


    }

    fun resetBiometricData(tag: Tag): NfcActionResult.ResetBiometrics {
        log("----- BiometricsAPI Reset BiometricData")

        val result = try {
            sendAndConfirm(
                apduCommand = APDUCommand.RESET_BIOMETRIC_DATA.value,
                name = "Reset Biometric Data",
                tag = tag
            )

        } catch (e: SentrySDKError.ApduCommandError) {
            return if (e.code == APDUResponseCode.HOST_INTERFACE_TIMEOUT_EXPIRED.value) {
                NfcActionResult.ResetBiometrics.Failed("Operation Timeout")
            } else {
                NfcActionResult.ResetBiometrics.Failed("Reason code: ${e.code}")
            }
        }

        return NfcActionResult.ResetBiometrics.Success
    }


    /**
     * Retrieves the version of the Verify applet installed on the scanned card.
     *
     * @throws SentrySDKError.ApduCommandError containing the status word returned by the last failed `APDU` command.
     *
     */
    internal fun getVerifyAppletVersion(tag: Tag): VersionInfo {
        // Note: Due to the way Apple implemented APDU communication, it's possible to send a select command and receive a 9000 response
        // even though the applet isn't actually installed on the card. The BioVerify applet has always supported a versioning command,
        // so here we'll simply check if the command was processes, and if we get an 'instruction byte not supported' response, we assume
        // the BioVerify applet isn't installed.

        log("----- BiometricsAPI Get Verify Applet Version")
        log("     Selecting Verify Applet")

        send(
            apduCommand = APDUCommand.SELECT_VERIFY_APPLET.value,
            name = "Select Verify Applet",
            tag = tag
        )
        val response = send(
            apduCommand = APDUCommand.GET_VERIFY_APPLET_VERSION.value,
            name = "Get Verify Applet Version",
            tag = tag
        )

        return if (response.statusWord == APDUResponseCode.OPERATION_SUCCESSFUL.value) {
            val responseBuffer = response.data

            when (responseBuffer.size) {
                5 -> {
                    val majorVersion = responseBuffer[3].toInt()
                    val minorVersion = responseBuffer[4].toInt()
                    VersionInfo(
                        isInstalled = true,
                        majorVersion = majorVersion,
                        minorVersion = minorVersion,
                        hotfixVersion = 0,
                        text = null
                    )
                }

                4 -> {
                    val majorVersion = responseBuffer[2].toInt()
                    val minorVersion = responseBuffer[3].toInt()
                    VersionInfo(
                        isInstalled = true,
                        majorVersion = majorVersion,
                        minorVersion = minorVersion,
                        hotfixVersion = 0,
                        text = null
                    )
                }

                2 -> {
                    val majorVersion = responseBuffer[0].toInt()
                    val minorVersion = responseBuffer[1].toInt()

                    VersionInfo(
                        isInstalled = true,
                        majorVersion = majorVersion,
                        minorVersion = minorVersion,
                        hotfixVersion = 0,
                        text = null
                    )

                }

                else -> {
                    throw SentrySDKError.CardOSVersionError
                }
            }
        } else if (response.statusWord == APDUResponseCode.INSTRUCTION_BYTE_NOT_SUPPORTED.value) {
            throw SentrySDKError.CardOSVersionError
        } else {
            throw SentrySDKError.ApduCommandError(response.statusWord)
        }
    }

    /**
     * Retrieves the version of the Enrollment applet installed on the scanned card (only available on version 2.0 or greater).
     * - Note: If the Enrollment applet version on the card is earlier than 2.0, this returns -1 for all version values.
     *
     * @param tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     * @return VersionInfo structure containing version information.
     * This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.

     */
    fun getEnrollmentAppletVersion(tag: Tag): VersionInfo {
        log("----- BiometricsAPI Get Enrollment Applet Version")
        log("     Selecting Enroll Applet")

        val response = sendAndConfirm(
            apduCommand = APDUCommand.SELECT_ENROLL_APPLET.value,
            name = "Select Enroll Applet",
            tag = tag
        )

        val responseBuffer = response.data

        if (responseBuffer.size < 16) {
            throw SentrySDKError.CardOSVersionError
        } else {
            val string = responseBuffer.toString(Charsets.US_ASCII)
            val majorVersion = responseBuffer[13].toInt() - 0x30
            val minorVersion = responseBuffer[15].toInt() - 0x30
            return VersionInfo(
                isInstalled = true,
                majorVersion = majorVersion,
                minorVersion = minorVersion,
                hotfixVersion = 0,
                text = string
            )
        }
    }

    /**
    Retrieves the version of the CDCVM applet installed on the scanned card (only available on version 2.0 or greater).

    - Note: If the CDCVM applet version on the card is earlier than 2.0, this returns -1 for all version values.

    - Parameters:
    - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.

    - Returns: A `VersionInfo` structure containing version information.

    This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.

     */
    fun getCVMAppletVersion(tag: Tag): VersionInfo {
        log("----- BiometricsAPI Get CVM Applet Version")

        val response = sendAndConfirm(
            apduCommand = APDUCommand.SELECT_CVM_APPLET.value,
            name = "Select CVM Applet",
            tag = tag
        )

        val responseBuffer = response.data

        return if (responseBuffer.size > 11) {
            val string = responseBuffer
                .filter { it in 0x20..0x7E }
                .toByteArray()
                .toString(Charsets.US_ASCII)
            val majorVersion = responseBuffer[10].toInt() - 0x30
            val minorVersion = responseBuffer[12].toInt() - 0x30
            VersionInfo(
                isInstalled = true,
                majorVersion = majorVersion,
                minorVersion = minorVersion,
                hotfixVersion = 0,
                text = string
            )
        } else {
            throw SentrySDKError.CvmAppletError(responseBuffer.size)
        }
    }


    /**
     * Scans the finger currently on the fingerprint sensor, indicating if the scanned fingerprint matches one recorded during enrollment.
     *
     * @param: tag Nfc tag
     *
     * @return fingerprint match
     *
     * This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.cvmAppletNotAvailable` if the CVM applet was unavailable for some reason.
     * `SentrySDKError.cvmAppletBlocked` if the CVM applet is in a blocked state and can no longer be used.
     * `SentrySDKError.cvmAppletError` if the CVM applet returned an unexpected error code.
     *
     */
    fun getFingerprintVerification(tag: Tag): Boolean {
        log("----- BiometricsAPI Get Fingerprint Verification")


        val returnData = send(
            apduCommand = APDUCommand.GET_FINGERPRINT_VERIFY.value,
            name = "Fingerprint Verification",
            tag = tag
        )

        if (returnData.statusWord == APDUResponseCode.OPERATION_SUCCESSFUL.value) {
            if (returnData.data[3] == 0x00.toByte()) {
                throw SentrySDKError.CvmAppletNotAvailable
            }

            if (returnData.data[5] == 0x01.toByte()) {
                throw SentrySDKError.CvmAppletBlocked
            }

            if (returnData.data[4] == 0xA5.toByte()) {
                log("     Match")
                return true
            }

            if (returnData.data[4] == 0x5A.toByte()) {
                log("     No match found")
                return false
            }

            throw SentrySDKError.CvmAppletError(returnData.data[4].toInt())
        }

        throw SentrySDKError.ApduCommandError(returnData.statusWord)
    }

    fun getCardOSVersion(tag: Tag): VersionInfo {
        log("----- BiometricsAPI Get Card OS Version")
        log("     Getting card OS version")

        val returnData = sendAndConfirm(
            apduCommand = APDUCommand.GET_OS_VERSION.value,
            name = "Get Card OS Version",
            tag = tag
        )

        log("     Processing response")
        val dataBuffer = returnData.data


        if (dataBuffer.size < 8) {
            throw SentrySDKError.CardOSVersionError
        }

        if (dataBuffer[0] != 0xFE.toByte()) {
            throw SentrySDKError.CardOSVersionError
        }
        if (dataBuffer[1] < 0x40.toByte()) {
            throw SentrySDKError.CardOSVersionError
        }
        if (dataBuffer[2] != 0x7f.toByte()) {
            throw SentrySDKError.CardOSVersionError
        }
        if (dataBuffer[3] != 0x00.toByte()) {
            throw SentrySDKError.CardOSVersionError
        }
        if (dataBuffer[4] < 0x40.toByte()) {
            throw SentrySDKError.CardOSVersionError
        }
        if (dataBuffer[5] != 0x9f.toByte()) {
            throw SentrySDKError.CardOSVersionError
        }
        if (dataBuffer[6] != 0x01.toByte()) {
            throw SentrySDKError.CardOSVersionError
        }

        val n = dataBuffer[7]
        var p: Int = 8 + n

        if (dataBuffer[p] != 0x9F.toByte()) {
            throw SentrySDKError.CardOSVersionError
        }
        p += 1
        if (dataBuffer[p] != 0x02.toByte()) {
            throw SentrySDKError.CardOSVersionError
        }
        p += 1
        if (dataBuffer[p].toInt() != 5) {
            throw SentrySDKError.CardOSVersionError
        }
        p += 1

        val major = dataBuffer[p] - 0x30
        p += 2
        val minor = dataBuffer[p] - 0x30
        p += 2
        val hotfix = dataBuffer[p] - 0x30

        return VersionInfo(
            isInstalled = true,
            majorVersion = major,
            minorVersion = minor,
            hotfixVersion = hotfix,
            text = null
        )

    }

    private fun log(text: String) {
        if (isDebugOutputVerbose) {
            println(text)
        }
    }

}

private fun Tag.transceive(bytes: ByteArray): ByteArray = IsoDep.get(this).transceive(bytes)
