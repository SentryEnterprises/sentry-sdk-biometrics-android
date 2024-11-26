package com.sentrycard.sentry.sdk.models

sealed class NfcAction {
    data object VerifyBiometric : NfcAction()
    data object GetVersionInformation : NfcAction()
    data object ResetBiometricData : NfcAction()
    data object EnrollFingerprint : NfcAction()
    data class GetEnrollmentStatus(
        val pinCode: String
    ) : NfcAction()
}

sealed class NfcActionResult {

    data class BiometricEnrollment(
        val isStatusEnrollment: Boolean,
    ) : NfcActionResult()

    sealed class ResetBiometrics() : NfcActionResult() {
        data object Success : ResetBiometrics()
        data class Failed(val reason: String) : ResetBiometrics()
    }

    data class VerifyBiometric(
        val fingerprintValidation: FingerprintValidation,
    ) : NfcActionResult()

    data class VersionInformation(
        val osVersion: VersionInfo,
        val enrollAppletVersion: VersionInfo,
        val cvmAppletVersion: VersionInfo,
        val verifyAppletVersion : VersionInfo,
    ) : NfcActionResult()

    sealed class EnrollFingerprint(): NfcActionResult() {
        data object Complete : EnrollFingerprint()
        data object Failed : EnrollFingerprint()
    }

}
