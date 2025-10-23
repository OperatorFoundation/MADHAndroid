package org.operatorfoundation.madh

/**
 * Represents a decimal confirmation code derived from the MA-DH out-of-band value.
 * This code is compared out-of-band (e.g., verbally over a phone call) to verify key confirmation.
 */
data class ConfirmationCode(val code: String)
