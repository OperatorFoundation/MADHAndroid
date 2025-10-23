package org.operatorfoundation.madh.types

/**
 * Represents a confirmation value used in MA-DH key confirmation.
 */
data class Confirmation(val bytes: ByteArray)
{
    override fun equals(other: Any?): Boolean {
        if (this == other) return true
        if (other !is Confirmation) return false

        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int
    {
        return bytes.contentHashCode()
    }
}
