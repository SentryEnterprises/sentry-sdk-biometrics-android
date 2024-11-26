package com.sentrycard.sentry.sdk.models


data class VersionInfo (
    // Indicates if the queried object is installed on the card
    val isInstalled: Boolean,

    // The major version number (increments on major functionality changes).
    val majorVersion: Int,

    // The minor version number (increments on minor functionality changes).
    val minorVersion: Int,

    // The hotfix version number (increments only on emergency bug fixes).
    val hotfixVersion: Int,

    // A textual representation of the data returned by the queried object.
    val text: String?,
) {
    override fun toString(): String = if (isInstalled) {
        val optionalText = text?.let { " ($it)" } ?: ""
        "$majorVersion.$minorVersion.$hotfixVersion$optionalText"
    } else {
        "Not installed"
    }

}
