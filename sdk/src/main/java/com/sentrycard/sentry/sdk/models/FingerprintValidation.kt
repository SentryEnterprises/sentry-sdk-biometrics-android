package com.sentrycard.sentry.sdk.models


/**
 * Indicates the results of a fingerprint validation.
 */
enum class FingerprintValidation {
    // The finger on the sensor matches the fingerprints recorded during enrollment.
    MatchValid,

    // The finger on the sensor does not match the fingerprints recorded during enrollment.
    MatchFailed,

    // The card is not enrolled and fingerprint verification cannot be performed.
    NotEnrolled
}

/**
 * Contains a value indicating if the fingerprint on the sensor matches the one recorded during enrollment, and any data stored on the card during the enrollment process.
 */
data class FingerprintValidationAndData(
    // `.matchValid` if the scanned fingerprint matches the one recorded during enrollment; otherwise `.matchFailed` (or `.notEnrolled` if the card is not enrolled and validation cannot be performed).
    val doesFingerprintMatch: FingerprintValidation,

    // Contains any data stored during the enrollment process. If no data was stored during enrollment, this array is empty.
    val storedData: ByteArray
)