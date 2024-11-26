package com.sentrycard.sentry.sdk.models

/**
 * Indicates the card's biometric mode.
 */
sealed class BiometricMode {
    // the card is in enrollment mode and will accept fingerprint enrollment commands
    data object Enrollment : BiometricMode()

    // the card is in verification mode
    data object Verification : BiometricMode()
}

/**
 * Describes the number of enrolled touches and remaining touches for a finger.
 */
data class FingerTouches(
    // Indicates the number of currently enrolled touches (in the range 0 - 6).
    val enrolledTouches: Int,

    // Indicates the number of touches remaining to be enrolled (in the range 0 - 6).
    val remainingTouches: Int,

    // Indicates the state of the enrolled finger: 0 = no touches enrolled, 1 = touches done but qualification touch needed (i.e. `verifyEnrolledFingerprint()`), 2 = finger is enrolled, additional template saved on first match, 3 = finger fully enrolled.
    val biometricMode: Int?,
)

/**
 * Encapsulates the information returned from querying the card for its enrollment status.
 */
data class BiometricEnrollmentStatus(

    // Indicates what properties contain values; 0 = `biometricMode` property of `FingerTouches` is nil, 1 = `biometricMode` property of `FingerTouches` contains data.
    val version: Int,

    // One (1) for Enroll applet prior to 2.1, two (2) for Enroll applet 2.1 or later.
    val maximumFingers: Int,

    /// Enrollment data for each supported finger.
    val enrollmentByFinger: List<FingerTouches>,

    // The index of the next finger to enroll, starting at one (1).
    val nextFingerToEnroll: Int,

    // Indicates the card's enrollment mode (either available for enrollment or ready to verify fingerprints).
    val mode: BiometricMode,
)

sealed class BiometricProgress {
    data class FingerTransition(val nextFingerIndex: Int) : BiometricProgress()
    data class Feedback(val status: String) : BiometricProgress()
    data class Progressing(
        val currentFinger: Int, // this counts from 1
        val currentStep: Int,
        val totalSteps: Int,
    ) : BiometricProgress() {
        val remainingTouches = totalSteps - currentStep
    }
}