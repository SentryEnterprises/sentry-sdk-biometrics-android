package com.sentrycard.sentry.sdk.presentation


sealed class SentrySDKError : Exception() {
    // These errors can occur in production.

    //  Individual enroll code digits must be in the range 0 - 9.
    data object EnrollCodeDigitOutOfBounds : SentrySDKError()

    //  The enroll code must be between 4 - 6 characters in length.
    data object EnrollCodeLengthOutOfBounds : SentrySDKError()

    //  We have an NFC connection, but no ISO7816 tag.
    data object IncorrectTagFormat : SentrySDKError()

    //  APDU specific error.
    data class ApduCommandError(val code: Int) : SentrySDKError()

    //  The applets on the SentryCard do not appear to support secure communication.
    data object SecureCommunicationNotSupported : SentrySDKError()

    //  The amount of data the system attempted to store on the SentryCard was too big (maximum size supported is 2048 bytes).
    data object DataSizeNotSupported : SentrySDKError()

    //  The CVM applet on the SentryCard was unavailable.
    data object CvmAppletNotAvailable : SentrySDKError()

    // Indicates that the Enroll applet on the scanned card is not currently supported.
    data class UnsupportedEnrollAppletVersion(val version: Int) : SentrySDKError()

    // The valid finger index values are currently 1 and 2.
    data object InvalidFingerIndex : SentrySDKError()

    //  The CVM applet on the SentryCard is blocked, and the SentryCard will need a reset.
    data object CvmAppletBlocked : SentrySDKError()

    // Indicates that the CVM applet return an unexpected code.
    data class CvmAppletError(val code: Int) : SentrySDKError()

    //  The BioVerify applet is not installed on the SentryCard.
    data object BioverifyAppletNotInstalled : SentrySDKError()

    //  Indicates that the SentryCard is already enrolled and is in verification state.
    data object EnrollModeNotAvailable : SentrySDKError()

    data object EnrollVerificationError : SentrySDKError()

    //  TEMPORARY
    data object BioVerifyAppletWrongVersion : SentrySDKError()


    // The following errors should never occur, and indicate bugs in the code.

    //  The buffer returned from querying the card for its biometric enrollment status was unexpectedly too small. This indicates something has changed in either the OS running on the scanned device or the Enroll applet itself.
    data object EnrollmentStatusBufferTooSmall : SentrySDKError()

    //  The buffer used in the `NFCISO7816APDU` constructor was not a valid `APDU` command. This should only occur if CoreNFC changes dramatically, or the APDU command itself is incorrect and was never tested.
    data object InvalidAPDUCommand : SentrySDKError()

    //  We have an NFC connection, but no NFC tag. This should only happen if something has changed in the SentrySDK and the connection logic is incorrect.
    data object ConnectedWithoutTag : SentrySDKError()

    //  Indicates that a secure channel with the card could not be created.
    data object SecureChannelInitializationError : SentrySDKError()

    //  Indicates an error in the data buffer returned from querying the SentryCard OS version.
    data object CardOSVersionError : SentrySDKError()

    //  Indicates an error occurred generating the public/private key pair, or other keys.
    data object KeyGenerationError : SentrySDKError()

    //  Indicates an error extracting the shared secrets data.
    data object SharedSecretExtractionError : SentrySDKError()
}