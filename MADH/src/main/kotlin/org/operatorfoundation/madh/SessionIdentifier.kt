package org.operatorfoundation.madh

/**
 * Represents a unique session identifier used in MA-DH key confirmation.
 */
data class SessionIdentifier(val bytes: ByteArray)
{
    override fun equals(other: Any?): Boolean {
        if (this == other) return true
        if (other !is SessionIdentifier) return false

        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int
    {
        return bytes.hashCode()
    }
}
