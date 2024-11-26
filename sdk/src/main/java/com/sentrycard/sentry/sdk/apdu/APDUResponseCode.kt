package com.sentrycard.sentry.sdk.apdu

enum class APDUResponseCode(val value: Int) {
    /// Normal operation.
    OPERATION_SUCCESSFUL(0x9000),

    /// Warning processing - state of non-volatile memory may have changed
    NO_MATCH_FOUND(0x6300),
    ENROLL_CODE_INCORRECT_THREE_TRIES_REMAIN(0x63C3),
    ENROLL_CODE_INCORRECT_TWO_TRIES_REMAIN(0x63C2),
    ENROLL_CODE_INCORRECT_ONE_TRIES_REMAIN(0x63C1),
    ENROLL_CODE_INCORRECT_ZERO_TRIES_REMAIN(0x63C0),

    /// Checking errors - wrong length
    WRONG_LENGTH(0x6700),
    FORMAT_NOT_COMPLIANT(0x6701),
    LENGTH_VALUE_NOT_THE_ONE_EXPECTED(0x6702),
    COMMUNICATION_FAILURE(0x6741),              // IDEX Enroll applet specific
    CALIBRATION_ERROR(0x6744),
    FINGER_REMOVED(0x6745),                     // IDEX Enroll applet specific
    POOR_IMAGE_QUALITY(0x6747),                  // IDEX Enroll applet specific
    USER_TIMEOUT_EXPIRED(0x6748),                // IDEX Enroll applet specific
    HOST_INTERFACE_TIMEOUT_EXPIRED(0x6749),       // IDEX Enroll applet specific

    /// Checking errors - command not allowed
    CONDITION_OF_USE_NOT_SATISFIED(0x6985),

    /// Checking errors - wrong parameters
    NO_INFORMATION_GIVEN(0x6A00),
    INCORRECT_COMMAND_PARAMETERS(0x6A80),
    FUNCTION_NOT_SUPPORTED(0x6A81),
    APPLET_NOT_FOUND(0x6A82),
    RECORD_NOT_FOUND(0x6A83),
    NOT_ENOUGH_MEMORY(0x6A84),
    INCONSISTENT_WITH_TLV(0x6A85),
    INCORRECT_PARAMETERS(0x6A86),
    INCONSISTENT_WITH_PARAMETERS(0x6A87),
    DATA_NOT_FOUND(0x6A88),
    FILE_ALREADY_EXISTS(0x6A89),
    NAME_ALREADY_EXISTS(0x6A8A),

    /// Checking errors - wrong parameters
    WRONG_PARAMETERS(0x6B00),

    /// Checking errors - INS code not supported
    INSTRUCTION_BYTE_NOT_SUPPORTED(0x6D00),

    /// Checking errors - CLA code not supported
    CLASS_BYTE_NOT_SUPPORTED(0x6E00),

    /// Checking errors - no precise diagnosis
    COMMAND_ABORTED(0x6F00),
    NO_PRECISE_DIAGNOSIS(0x6F87),
    CARD_DEAD(0x6FFF)
}