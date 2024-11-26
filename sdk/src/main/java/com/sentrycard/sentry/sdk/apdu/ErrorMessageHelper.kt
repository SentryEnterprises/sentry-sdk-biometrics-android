package com.sentrycard.sentry.sdk.apdu

import android.nfc.TagLostException
import com.sentrycard.sentry.sdk.presentation.SentrySDKError
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.ApduCommandError
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.BioVerifyAppletWrongVersion
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.BioverifyAppletNotInstalled
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.CardOSVersionError
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.ConnectedWithoutTag
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.CvmAppletBlocked
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.CvmAppletError
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.CvmAppletNotAvailable
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.DataSizeNotSupported
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.EnrollCodeDigitOutOfBounds
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.EnrollCodeLengthOutOfBounds
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.EnrollModeNotAvailable
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.EnrollVerificationError
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.EnrollmentStatusBufferTooSmall
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.IncorrectTagFormat
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.InvalidAPDUCommand
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.KeyGenerationError
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.SecureChannelInitializationError
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.SecureCommunicationNotSupported
import com.sentrycard.sentry.sdk.presentation.SentrySDKError.SharedSecretExtractionError

// TODO: Localize all of these strings

fun Throwable?.getDecodedMessage() = when (this) {
    is SentrySDKError -> this.localizedErrorMessage()
    is TagLostException -> "Communication with the card has failed. Please move the phone away from the card briefly to reset the card, then try again."
    else -> this?.localizedMessage ?: "Unknown error $this"
}

fun SentrySDKError.localizedErrorMessage() = when (this) {
    is EnrollCodeDigitOutOfBounds -> "Individual enroll code digits must be in the range 0 - 9."
    is EnrollCodeLengthOutOfBounds -> "The enroll code must be between 4 - 6 characters in length."
    is IncorrectTagFormat -> "The card was scanned correctly, but it does not appear to be the correct format."
    is ApduCommandError -> {
        when (code) {
            APDUResponseCode.NO_MATCH_FOUND.value ->
                "No match found."

            APDUResponseCode.ENROLL_CODE_INCORRECT_THREE_TRIES_REMAIN.value ->
                "The enroll code on the scanned card does not match the enroll code set in the application (three tries remaining)."

            APDUResponseCode.ENROLL_CODE_INCORRECT_TWO_TRIES_REMAIN.value ->
                "The enroll code on the scanned card does not match the enroll code set in the application (two tries remaining)."

            APDUResponseCode.ENROLL_CODE_INCORRECT_ONE_TRIES_REMAIN.value ->
                "The enroll code on the scanned card does not match the enroll code set in the application (one try remaining)."

            APDUResponseCode.ENROLL_CODE_INCORRECT_ZERO_TRIES_REMAIN.value ->
                "The enroll code on the scanned card does not match the enroll code set in the application (zero tries remaining)."

            APDUResponseCode.WRONG_LENGTH.value ->
                "Length parameter incorrect."

            APDUResponseCode.FORMAT_NOT_COMPLIANT.value ->
                "Command APDU format not compliant with this standard."

            APDUResponseCode.LENGTH_VALUE_NOT_THE_ONE_EXPECTED.value ->
                "The length parameter value is not the one expected."

            APDUResponseCode.COMMUNICATION_FAILURE.value ->
                "Communication with the card has failed.  Please move the phone away from the card briefly to reset the card, then try again."

            APDUResponseCode.FINGER_REMOVED.value ->
                "The finger was removed from the sensor before the scan completed. Please try again."

            APDUResponseCode.POOR_IMAGE_QUALITY.value ->
                "The image scanned by the sensor was poor quality, please try again."

            APDUResponseCode.USER_TIMEOUT_EXPIRED.value ->
                "No finger was detected on the sensor. Please try again."

            APDUResponseCode.HOST_INTERFACE_TIMEOUT_EXPIRED.value ->
                "Communication with the card has failed.  Please move the phone away from the card briefly to reset the card, then try again."

            APDUResponseCode.CONDITION_OF_USE_NOT_SATISFIED.value ->
                "Conditions of use not satisfied."

            APDUResponseCode.NOT_ENOUGH_MEMORY.value ->
                "Not enough memory space in the file."

            APDUResponseCode.WRONG_PARAMETERS.value ->
                "Parameter bytes are invalid."

            APDUResponseCode.INSTRUCTION_BYTE_NOT_SUPPORTED.value ->
                "Instruction byte not supported or invalid."

            APDUResponseCode.CLASS_BYTE_NOT_SUPPORTED.value ->
                "Class byte not supported or invalid."

            APDUResponseCode.COMMAND_ABORTED.value ->
                "Command aborted – more exact diagnosis not possible (e.g. operating system error)."

            APDUResponseCode.NO_PRECISE_DIAGNOSIS.value ->
                "An error occurred while communicating with the card. Move the card away from the phone and try again."

            APDUResponseCode.CARD_DEAD.value ->
                "Card dead (overuse)."

            APDUResponseCode.CALIBRATION_ERROR.value ->
                "The fingerprint sensor is returning a calibration error."

            APDUResponseCode.NO_INFORMATION_GIVEN.value -> "No information given."

            APDUResponseCode.INCORRECT_COMMAND_PARAMETERS.value ->
                "Incorrect parameters in the command data field."

            APDUResponseCode.FUNCTION_NOT_SUPPORTED.value ->
                "Function not supported."

            APDUResponseCode.APPLET_NOT_FOUND.value ->
                "Applet not found."

            APDUResponseCode.RECORD_NOT_FOUND.value ->
                "Record not found."

            APDUResponseCode.INCONSISTENT_WITH_TLV.value ->
                "Inconsistent with TLV structure."

            APDUResponseCode.INCORRECT_PARAMETERS.value ->
                "Incorrect parameters P1-P2."

            APDUResponseCode.INCONSISTENT_WITH_PARAMETERS.value ->
                "Inconsistent with parameters P1-P2."

            APDUResponseCode.DATA_NOT_FOUND.value ->
                "Referenced data or DO not found."

            APDUResponseCode.FILE_ALREADY_EXISTS.value ->
                "File already exists or sensor is already calibrated."

            APDUResponseCode.NAME_ALREADY_EXISTS.value ->
                "DF name already exists."

            else -> "Unknown Error Code: $code"
        }

    }

    is SecureCommunicationNotSupported -> "Applets on the scanned card do not support encryption. Please open Settings and turn the Secure Communication option off, then try again."
    is DataSizeNotSupported -> "Unable to store data to SentryCard: maximum size supported is 2048 bytes."
    is CvmAppletNotAvailable -> "Unable to initialize the CVM applet on the SentryCard."
    is CvmAppletBlocked -> "The CVM applet on the SentryCard is blocked."
    is CvmAppletError -> "Communication with the card has failed. Please move the phone away from the card briefly to reset the card, then try again."
    is BioverifyAppletNotInstalled -> "The SentryCard does not contain the BioVerify applet. This applet is required. Please run the applet install script to install the required applets."
    is EnrollModeNotAvailable -> "The SentryCard is already enrolled. To re-enroll, go into Options and reset biometric enrollment data."
    is EnrollVerificationError -> "The system was unable to verify that the enrolled fingerprints match the finger on the sensor. Please restart enrollment and try again."
    is BioVerifyAppletWrongVersion -> "This SentryCard has an unsupported version of the BioVerify applet installed."
    is EnrollmentStatusBufferTooSmall -> "The buffer returned from querying the card for its biometric enrollment status was unexpectedly too small."
    is InvalidAPDUCommand -> "The buffer used was not a valid `APDU` command."
    is ConnectedWithoutTag -> "NFC connection to card exists, but no tag."
    is SecureChannelInitializationError -> "Unable to initialize secure communication channel."
    is CardOSVersionError -> "Unexpected return value from querying card for OS version."
    is KeyGenerationError -> "Key generation error."
    is SharedSecretExtractionError -> "Shared secret extract error."
    SentrySDKError.InvalidFingerIndex -> "Unexpected finger index"
    is SentrySDKError.UnsupportedEnrollAppletVersion -> {
        "Unsupported enrollment version $version"
    }
}