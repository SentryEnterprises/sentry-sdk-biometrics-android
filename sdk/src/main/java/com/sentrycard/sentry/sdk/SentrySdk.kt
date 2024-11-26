package com.sentrycard.sentry.sdk

import android.nfc.Tag
import android.nfc.tech.IsoDep
import com.sentrycard.sentry.sdk.presentation.SentrySDKError
import com.sentrycard.sentry.sdk.apdu.APDUResponseCode
import com.sentrycard.sentry.sdk.biometrics.BiometricsApi
import com.sentrycard.sentry.sdk.biometrics.DataSlot
import com.sentrycard.sentry.sdk.configuration.SentrySDKConstants
import com.sentrycard.sentry.sdk.models.BiometricMode
import com.sentrycard.sentry.sdk.models.BiometricMode.Enrollment
import com.sentrycard.sentry.sdk.models.BiometricMode.Verification
import com.sentrycard.sentry.sdk.models.BiometricProgress
import com.sentrycard.sentry.sdk.models.FingerprintValidation
import com.sentrycard.sentry.sdk.models.FingerprintValidationAndData
import com.sentrycard.sentry.sdk.models.NfcActionResult
import com.sentrycard.sentry.sdk.models.NfcActionResult.BiometricEnrollment
import kotlinx.coroutines.delay
import java.io.IOException
import kotlin.time.Duration.Companion.seconds

/**
 * Entry point for the `SentrySDK` functionality. Provides methods exposing all available functionality.
 *
 * This class controls and manages an actively connected `Tag` via `APDU` commands.
 *
 * The bioverify.cap, com.idex.enroll.cap, and com.jnet.CDCVM.cap applets must be installed on the SentryCard for full access to all functionality of this SDK.
 */
class SentrySdk(
    private val enrollCode: ByteArray,
    private val isDebugOutputVerbose: Boolean = true,
) {
    private val biometricsAPI: BiometricsApi = BiometricsApi(
        isDebugOutputVerbose = isDebugOutputVerbose,
    )

    val sdkVersion = "0.0.1"

    /**
     * Retrieves the biometric fingerprint enrollment status.
     *
     * Sends `APDU` commands to a java applet running on the connected SentryCard.
     *
     * @return BiometricEnrollment fingerprint enrollment status
     *
     * This method can throw the following exceptions:
     * `SentrySDKError.EnrollCodeLengthOutOfbounds` if `enrollCode` is less than four (4) characters or more than six (6) characters in length.
     * `SentrySDKError.ApduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.EnrollCodeDigitOutOfBounds` if an enroll code digit is not in the range 0-9.
     * `SentrySDKError.IncorrectTagFormat` if an NFC session scanned a tag, but it is not an ISO7816 tag.
     * `NFCReaderError` if an error occurred during the NFC session (includes user cancellation of the NFC session).
     */
    fun getEnrollmentStatus(tag: Tag): BiometricEnrollment {
        biometricsAPI.initializeEnroll(tag = tag, enrollCode = enrollCode)

        val enrollStatus = biometricsAPI.getEnrollmentStatus(tag = tag)
        return BiometricEnrollment(enrollStatus.mode == Enrollment)

    }

    /**
     * Writes data to the indicated data slot on the SentryCard. A biometric verification is performed first before writing the data. The `.small` data slot holds up to 255 bytes of data, and the `.huge` data slot holds up to 2048 bytes of data.
     *
     * Opens an `NFCReaderSession`, connects to an `NFCISO7816Tag` through this session, and sends `APDU` commands to a java applet running on the connected SentryCard.
     *
     * - Note: The BioVerify applet does not currently support secure communication, so a secure channel is not used.
     *
     * - Parameters:
     * - dataToStore: An array of `UInt8`bytes to write to the indicated data slot.
     * - dataSlot: The data slot to which the data is written.
     * - connected: A callback method that receives an `NFCReaderSession` and a boolean value. The `NFCReaderSession` allows the caller to update the NFC UI to indicate state. The boolean value is `true` when an NFC connection is made and an ISO7816 tag is detected, and `false` when the connection is dropped.
     *
     * - Returns: `FingerprintValidation.matchValid` if the scanned fingerprint matches the one recorded during enrollment. If there is a successful match, the indicated data is written to the indicated data slot. Otherwise, returns  `FingerprintValidation.matchFailed` if the scanned fingeprrint does not match, and `FingerprintValidation.notEnrolled` if the card is in verification mode (i.e. the card is not enrolled and thus a fingerprint validation could not be performed).
     *
     * This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.dataSizeNotSupported` if the `data` parameter is larger than 255 bytes in size for the `.small` data slot, or 2048 bytes for the `.huge` data slot.
     * `SentrySDKError.bioVerifyAppletNotInstalled` if the BioVerify applet is not installed on the scanned SentryCard.
     * `SentrySDKError.bioVerifyAppletWrongVersion` if the BioVerify applet installed on the SentryCard does not support data storage.
     * `SentrySDKError.cvmAppletNotAvailable` if the CVM applet was unavailable for some reason.
     * `SentrySDKError.cvmAppletBlocked` if the CVM applet is in a blocked state and can no longer be used.
     * `SentrySDKError.cvmAppletError` if the CVM applet returned an unexpected error code.
     * `NFCReaderError` if an error occurred during the NFC session (includes user cancellation of the NFC session).

     */
    fun storeDataSecure(
        dataToStore: ByteArray,
        dataSlot: DataSlot,
        tag: Tag
    ): FingerprintValidation {
        // throw an error if the caller is passing more than the allowed maximum size of stored data
        when (dataSlot) {
            DataSlot.Small -> {
                if (dataToStore.size > SentrySDKConstants.SMALL_MAX_DATA_SIZE) {
                    throw SentrySDKError.DataSizeNotSupported
                }
            }

            DataSlot.Huge -> {
                if (dataToStore.size > SentrySDKConstants.HUGE_MAX_DATA_SIZE) {
                    throw SentrySDKError.DataSizeNotSupported
                }
            }
        }


        // initialize the Enroll applet
        biometricsAPI.initializeEnroll(tag, enrollCode)
        val status = biometricsAPI.getEnrollmentStatus(tag)

        // if we are in verification mode...
        if (status.mode is Verification) {
            // initialize the BioVerify applet
            biometricsAPI.initializeVerify(tag)

            // store the data
            val result = biometricsAPI.setVerifyStoredDataSecure(tag, dataToStore, dataSlot)

            return if (result) FingerprintValidation.MatchValid else FingerprintValidation.MatchFailed
        } else {
            // otherwise, this card isn't enrolled and a validation cannot be performed
            return FingerprintValidation.NotEnrolled
        }

    }


    /**
     * Retrieves the data stored in the indicated data slot on the SentryCard. A biometric verification is performed first before retrieving the data.
     *
     * Sends `APDU` commands to a java applet running on the connected SentryCard.
     *
     * - Note: The BioVerify applet does not currently support secure communication, so a secure channel is not used.
     *
     *  - Parameters:
     *  - dataSlot: The data slot from which data is retrieved.
     *  - connected: A callback method that receives an `NFCReaderSession` and a boolean value. The `NFCReaderSession` allows the caller to update the NFC UI to indicate state. The boolean value is `true` when an NFC connection is made and an ISO7816 tag is detected, and `false` when the connection is dropped.
     *
     *  - Returns: A `FingerprintValidationAndData` structure indicating if the finger on the sensor matches the fingerprint recorded during enrollment. If there is a successful match, this structure also contains the data stored in the indicated data slot. The `.small` data slot returns up to 255 bytes of data. The `.huge` data slot returns up to 2048 bytes of data.
     *
     *  This method can throw the following exceptions:
     *   * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     *   * `SentrySDKError.bioVerifyAppletNotInstalled` if the BioVerify applet is not installed on the scanned SentryCard.
     *   * `SentrySDKError.bioVerifyAppletWrongVersion` if the BioVerify applet installed on the SentryCard does not support data storage.
     *   * `SentrySDKError.cvmAppletNotAvailable` if the CVM applet was unavailable for some reason.
     *   * `SentrySDKError.cvmAppletBlocked` if the CVM applet is in a blocked state and can no longer be used.
     *   * `SentrySDKError.cvmAppletError` if the CVM applet returned an unexpected error code.
     *   * `NFCReaderError` if an error occurred during the NFC session (includes user cancellation of the NFC session).
     */
    fun retrieveDataSecure(
        dataSlot: DataSlot,
        tag: Tag
    ): FingerprintValidationAndData {

        // initialize the Enroll applet
        biometricsAPI.initializeEnroll(tag = tag, enrollCode = enrollCode)

        val status = biometricsAPI.getEnrollmentStatus(tag = tag)

        // if we are in verification mode...
        if (status.mode == BiometricMode.Verification) {
            // initialize the BioVerify applet
            biometricsAPI.initializeVerify(tag = tag)

            // store the data
            return biometricsAPI.getVerifyStoredDataSecure(tag = tag, dataSlot = dataSlot)
        } else {
            // otherwise, this card isn't enrolled and a validation cannot be performed
            return FingerprintValidationAndData(
                doesFingerprintMatch = FingerprintValidation.NotEnrolled,
                storedData = byteArrayOf()
            )
        }

    }

    suspend fun enrollFingerprint(
        tag: Tag,
        resetOnFirstCall: Boolean = false,
        onBiometricProgressChanged: (BiometricProgress) -> Unit
    ): NfcActionResult.EnrollFingerprint {
        log("SentrySdk enrollFingerprint")
        var currentFinger: Int = 1           // this counts from 1 in the IDEX Eroll applet
        var resetOnFirstCall = resetOnFirstCall

        try {
            biometricsAPI.initializeEnroll(tag = tag, enrollCode = enrollCode)

            val enrollStatus = biometricsAPI.getEnrollmentStatus(tag = tag)
            log("SentrySdk enrollFingerprint enrollStatus $enrollStatus")
            // if this card is in verification mode, we cannot enroll fingerprints
            if (enrollStatus.mode is BiometricMode.Verification) {
                throw SentrySDKError.EnrollModeNotAvailable
            }

            // the next finger index
            currentFinger = enrollStatus.nextFingerToEnroll

            log("SentrySdk enrollFingerprint currentFinger $currentFinger")

            while ((currentFinger - 1) < enrollStatus.maximumFingers) {
                val maxStepsForFinger =
                    enrollStatus.enrollmentByFinger[currentFinger - 1].enrolledTouches +
                            enrollStatus.enrollmentByFinger[currentFinger - 1].remainingTouches

                // if we're resetting, assume we have not yet enrolled anything
                var enrollmentsLeft =
                    if (resetOnFirstCall) {
                        maxStepsForFinger
                    } else {
                        enrollStatus.enrollmentByFinger[currentFinger - 1].remainingTouches
                    }

                while (enrollmentsLeft > 0) {

                    log("SentrySdk enrollFingerprint enrollmentsLeft $enrollmentsLeft")

                    // inform listeners about the current state of enrollment for this finger
                    onBiometricProgressChanged(
                        BiometricProgress.Progressing(
                            currentFinger = currentFinger,
                            currentStep = maxStepsForFinger - enrollmentsLeft,
                            totalSteps = maxStepsForFinger
                        )
                    )

                    try {
                        // scan the finger currently on the sensor
                        enrollmentsLeft = if (resetOnFirstCall) {
                            biometricsAPI
                                .resetEnrollAndScanFingerprint(
                                    tag = tag,
                                    fingerIndex = currentFinger
                                )
                                .enrollmentByFinger[currentFinger - 1]
                                .remainingTouches
                        } else {
                            biometricsAPI
                                .enrollScanFingerprint(tag = tag, fingerIndex = currentFinger)
                                .enrollmentByFinger[currentFinger - 1]
                                .remainingTouches
                        }
                    } catch (e: SentrySDKError.ApduCommandError) {

                        when (e.code) {
                            APDUResponseCode.POOR_IMAGE_QUALITY.value -> {}// ignore
                            else -> {
                                throw e
                            }
                        }
                    }

                    resetOnFirstCall = false

                    // inform listeners of the step that just finished
                    onBiometricProgressChanged(
                        BiometricProgress.Progressing(
                            currentFinger = currentFinger,
                            currentStep = maxStepsForFinger - enrollmentsLeft,
                            totalSteps = maxStepsForFinger
                        )
                    )
                }

                onBiometricProgressChanged(
                    BiometricProgress.Progressing(
                        currentFinger = currentFinger,
                        currentStep = maxStepsForFinger,
                        totalSteps = maxStepsForFinger
                    )
                )
                log("SentrySdk verifyEnrolled")

                try {
                    biometricsAPI.verifyEnrolledFingerprint(tag = tag)

                } catch (e: SentrySDKError.ApduCommandError) {
                    if (e.code == APDUResponseCode.NO_MATCH_FOUND.value) {
                        // expose a custom error if the verify enrolled fingerprint command didn't find a match
                        throw SentrySDKError.EnrollVerificationError
                    } else {
                        throw e
                    }
                }

                if (currentFinger < enrollStatus.maximumFingers) {
                    onBiometricProgressChanged(BiometricProgress.FingerTransition(currentFinger + 1))
                    log("SentrySdk enrollFingerprint sleeping for 2 seconds")
                    delay(2.seconds)
                }

                currentFinger += 1

                log("SentrySdk enrollFingerprint currentFinger $currentFinger")

            }
        } catch (e: SentrySDKError.ApduCommandError) {
            when (e.code) {
                APDUResponseCode.POOR_IMAGE_QUALITY.value,
                APDUResponseCode.HOST_INTERFACE_TIMEOUT_EXPIRED.value,
                APDUResponseCode.NO_PRECISE_DIAGNOSIS.value,
                100,
                102 -> {
                    // ignore these errors
                    return NfcActionResult.EnrollFingerprint.Failed
                }

                else -> {
                    throw e
                }
            }
        }

        return NfcActionResult.EnrollFingerprint.Complete
    }

    /**
     * Resets the biometric data recorded on the card. This effectively erases all fingerprint enrollment and puts the card into an unenrolled state.
     *
     * Opens an `NFCReaderSession`, connects to an Nfc tag through this session, and sends `APDU` commands to a java applet running on the connected SentryCard.
     *
     * - Warning: This is for development purposes only! This command only works on development cards, and fails when used on production cards.
     */
    fun resetCard(tag: Tag): NfcActionResult.ResetBiometrics {
        // reset the biometric data, setting the card into an unenrolled state
        return biometricsAPI.resetBiometricData(tag = tag)

    }


    /**
     * Validates that the finger on the fingerprint sensor matches (or does not match) a fingerprint recorded during enrollment.
     *
     * Opens an `NFCReaderSession`, connects to an `Tag` through this session, and sends `APDU` commands to a java applet running on the connected SentryCard.
     *
     * This process waits up to five (5) seconds for a finger to be pressed against the sensor. This timeout is (currently) not configurable. If a finger is not detected on the sensor within the
     * timeout period, a `SentrySDKError.apduCommandError` is thrown, indicating either a user timeout expiration (0x6748) or a host interface timeout expiration (0x6749).
     *
     * @return scanned fingerprint matches with the enrolled biometric
     *
     * This method can throw the following exceptions:
     * `SentrySDKError.enrollCodeLengthOutOfbounds` if `enrollCode` is less than four (4) characters or more than six (6) characters in length.
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.enrollCodeDigitOutOfBounds` if an enroll code digit is not in the range 0-9.
     * `SentrySDKError.incorrectTagFormat` if an NFC session scanned a tag, but it is not an ISO7816 tag.
     * `SentrySDKError.cvmAppletNotAvailable` if the CVM applet on the SentryCard could not be initialized.
     * `SentrySDKError.cvmAppletBlocked` if the CVM applet on the SentryCard is blocked (likely requiring a full card reset).
     * `SentrySDKError.cvmAppletError` if the CVM applet returned an unexpected error code.
     * `NFCReaderError` if an error occurred during the NFC session (includes user cancellation of the NFC session).
     */
    fun validateFingerprint(tag: Tag): NfcActionResult.VerifyBiometric {

        biometricsAPI.initializeEnroll(tag = tag, enrollCode = enrollCode)
        val status = biometricsAPI.getEnrollmentStatus(tag)

        biometricsAPI.initializeVerify(tag = tag)
        return if (status.mode == Verification) {
            val isVerified = biometricsAPI.getFingerprintVerification(tag = tag)

            if (isVerified) {
                NfcActionResult.VerifyBiometric(FingerprintValidation.MatchValid)
            } else {
                NfcActionResult.VerifyBiometric(FingerprintValidation.MatchFailed)
            }

        } else {
            NfcActionResult.VerifyBiometric(FingerprintValidation.NotEnrolled)
        }

    }

    fun getCardSoftwareVersions(tag: Tag): NfcActionResult.VersionInformation {
        val osVersion = biometricsAPI
            .getCardOSVersion(tag = tag)
        log("OS= $osVersion")

        val verifyVersion = biometricsAPI
            .getVerifyAppletVersion(tag = tag)
        log("Verify= $verifyVersion")

        val enrollVersion = biometricsAPI
            .getEnrollmentAppletVersion(tag = tag)
        log("Enroll= $enrollVersion")

        val cvmVersion = biometricsAPI
            .getCVMAppletVersion(tag = tag)
        log("CVM= $cvmVersion")

        return NfcActionResult.VersionInformation(
            osVersion = osVersion,
            enrollAppletVersion = enrollVersion,
            cvmAppletVersion = cvmVersion,
            verifyAppletVersion = verifyVersion
        )
    }

    fun openConnection(tag: Tag): Boolean {
        val isoDep = IsoDep.get(tag)
        return try {
            if (!isoDep.isConnected) {
                isoDep.timeout = 30000
                isoDep.connect()
            }
            true
        } catch (e: IOException) {
            e.printStackTrace()
            false
        } catch (e: SecurityException) {
            log("Ignore SecurityException Tag out of date")
            e.printStackTrace()
            false
        }
    }

    fun closeConnection(tag: Tag) {
        val isoDep = IsoDep.get(tag)
        try {
            isoDep?.close()
        } catch (e: SecurityException) {
            log("Ignore SecurityException Tag out of date")
            e.printStackTrace()
        }
    }

    private fun log(text: String) {
        if (isDebugOutputVerbose) {
            println(text)
        }
    }
}