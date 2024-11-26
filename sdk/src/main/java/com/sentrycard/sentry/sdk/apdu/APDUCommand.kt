package com.sentrycard.sentry.sdk.apdu

import com.sentrycard.sentry.sdk.presentation.SentrySDKError.DataSizeNotSupported
import com.sentrycard.sentry.sdk.utils.intToByteArray
import kotlin.experimental.and
import kotlin.experimental.or

/**
Encapsulates the various `APDU` command bytes used throughout the SDK.

For more information on `APDU` commands, see the ISO7816-3 spec, ISO7816-4 spec, and the APDU Enrollment Device Specification from IDEX.
 */
enum class APDUCommand (val value: ByteArray) {
    // Selects the IDEX Enrollment applet (AID 494445585F4C5F0101)
    SELECT_ENROLL_APPLET(intToByteArray(0x00, 0xA4, 0x04, 0x00, 0x09, 0x49, 0x44, 0x45, 0x58, 0x5F, 0x4C, 0x5F, 0x01, 0x01, 0x00)),

    // Selects the CDCVM applet (AID F04A4E45545F1001)
    SELECT_CVM_APPLET(intToByteArray(0x00, 0xA4, 0x04, 0x00, 0x08, 0xF0, 0x4A, 0x4E, 0x45, 0x54, 0x5F, 0x10, 0x01, 0x00)),

    // Selects the Verify applet (AID 4A4E45545F0102030405)
    SELECT_VERIFY_APPLET(intToByteArray(0x00, 0xA4, 0x04, 0x00, 0x0A, 0x4A, 0x4E, 0x45, 0x54, 0x5F, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00)),

    // Gets the enrollment status.
    GET_ENROLL_STATUS(intToByteArray(0x84, 0x59, 0x04, 0x00, 0x01, 0x00)),

    // Verifies that the finger on the sensor matches the one recorded during enrollment.
    GET_FINGERPRINT_VERIFY(intToByteArray(0x80, 0xB6, 0x01, 0x00, 0x00)),

    // Enrolls a fingerprint.
    PROCESS_FINGERPRINT(intToByteArray(0x84, 0x59, 0x03, 0x00, 0x02, 0x00, 0x01)), // note: the last byte indicates the finger number; this will need updating if/when 2 fingers are supported

    // Enrolls a fingerprint and resets biometric data (used for restarting enrollment process).
    RESTART_ENROLL_AND_PROCESS_FINGERPRINT(intToByteArray(0x84, 0x59, 0x03, 0x00, 0x02, 0x02, 0x01)),





    // Verifies fingerprint enrollment.
    VERIFY_FINGERPRINT_ENROLLMENT(intToByteArray(0x84, 0x59, 0x00, 0x00, 0x01, 0x00)),

    // Retrieves the on-card OS version.
    GET_OS_VERSION(intToByteArray(0xB1, 0x05, 0x40, 0x00, 0x00)),

    // Retrieves the Verify applet version information.
    GET_VERIFY_APPLET_VERSION(intToByteArray(0x80, 0xCA, 0x5F, 0xC1, 0x00)),

    // Retrieves the data stored in the huge data slot of the Verify applet (requires biometric verification).
    GET_VERIFY_APPLET_STORED_DATA_HUGE_SECURED(intToByteArray(0x80, 0xCB, 0x01, 0xC2, 0x00, 0x0F, 0xFF)),       // up to 2048 bytes

    // Retrieves the data stored in the small data slot of the Verify applet.
    GET_VERIFY_APPLET_STORED_DATA_SMALL_UNSECURED(intToByteArray(0x80, 0xCA, 0x5F, 0xB0, 0xFF)),                // up to 255 bytes

    // Retrieves the data stored in the small data slot of the Verify applet (requires biometric verification).
    GET_VERIFY_APPLET_STORED_DATA_SMALL_SECURED(intToByteArray(0x80, 0xCB, 0x01, 0xD0, 0xFF)),                  // up to 255 bytes

    // Resets biometric data. DEVELOPMENT USE ONLY! This command works only on development cards.
    RESET_BIOMETRIC_DATA(intToByteArray(0xED, 0x57, 0xC1, 0x00, 0x01, 0x00));

    companion object {

        // Enrolls a fingerprint.
        fun processFingerprint(fingerIndex: Byte) = intToByteArray(0x84, 0x59, 0x03, 0x00, 0x02, 0x00) + fingerIndex

        // Enrolls a fingerprint and resets biometric data (used for restarting enrollment process).
        fun restartEnrollAndProcessFingerprint(fingerIndex: Byte) = intToByteArray(0x84, 0x59, 0x03, 0x00, 0x02, 0x02) + fingerIndex

        // Verifies the enroll code.
        fun verifyEnrollCode(code: ByteArray) =
            intToByteArray(0x80, 0x20, 0x00, 0x80, 0x08) + constructCodeBuffer(code)


        // Sets the enroll code.
        fun setEnrollCode(code: ByteArray) =
            intToByteArray(0x80, 0xE2, 0x08, 0x00, 0x0B, 0x90, 0x00, 0x08) + constructCodeBuffer(code)

        // Sets the data stored in the huge data slot of the Verify applet.
        // NOTE: Both the secure and unsecure version of this command write to the same data store slot
        // NOTE: This command is only included in case we want to reverse some changes to the way the large data slot is used. This command will likely become obsolete.
        fun setVerifyAppletStoredDataHugeUnsecure(data: ByteArray): ByteArray {
            if (data.size > HUGE_MAX_DATA_SIZE) {
                throw DataSizeNotSupported
            }

            val setVerifyAppletStoredData = intToByteArray(
                0x80, 0xDA, 0x5F, 0xC2, 0x00,
                ((data.size and 0xFF00) shr 8),
                data.size and 0x00FF,
            ) + data

            return setVerifyAppletStoredData
        }

        // Sets the data stored in the huge data slot of the Verify applet (requires biometric verification).
        fun setVerifyAppletStoredDataHugeSecure(data: ByteArray): ByteArray {
            if (data.size > HUGE_MAX_DATA_SIZE) {
                throw DataSizeNotSupported
            }

            val setVerifyAppletStoredData = intToByteArray(
                0x80, 0xDB, 0x01, 0xC2, 0x00,
                ((data.size and 0xFF00) shr 8),
                data.size and 0x00FF,
            ) + data

            return setVerifyAppletStoredData
        }

        // Sets the data stored in the small data slot of the Verify applet.
        fun setVerifyAppletStoredDataSmallUnsecure(data: ByteArray): ByteArray {
            if (data.size > HUGE_MAX_DATA_SIZE) {
                throw DataSizeNotSupported
            }

            val setVerifyAppletStoredData = intToByteArray(
                0x80, 0xDA, 0x5F, 0xB0,
                data.size and 0x00FF,
            ) + data

            return setVerifyAppletStoredData
        }

        // Sets the data stored in the small data slot of the Verify applet (requires biometric verification).
        fun setVerifyAppletStoredDataSmallSecure(data: ByteArray): ByteArray {
            if (data.size > HUGE_MAX_DATA_SIZE) {
                throw DataSizeNotSupported
            }

            val setVerifyAppletStoredData = intToByteArray(
                0x80, 0xDB, 0x01, 0xD0,
                data.size and 0x00FF,
            ) + data

            return setVerifyAppletStoredData
        }

        // Returns a padded buffer that contains the indicated enroll code digits.
        fun constructCodeBuffer(code: ByteArray): ByteArray {

            val codeBuffer: ByteArray = intToByteArray(
                0x20 + code.size,
            ) + code.asList().chunked(2).map {
                if (it.size > 1) {
                    (it[0].toInt() shl 4 and 0xF0).toByte() or (it[1] and 0x0F.toByte())
                } else {
                    (it[0].toInt() shl 4 and 0xF0).toByte() or (0x0F.toByte())
                }
            }.toByteArray().copyInto(
                ByteArray(7) { 0xFF.toByte() }
            )

            return codeBuffer
        }


        // The maximum amount of data (in bytes) that can be stored in the huge slot on the SentryCard.
        const val HUGE_MAX_DATA_SIZE = 2048

        // The maximum amount of data (in bytes) that can be stored in the small slot on the SentryCard.
        const val SMALL_MAX_DATA_SIZE = 255
    }


}
