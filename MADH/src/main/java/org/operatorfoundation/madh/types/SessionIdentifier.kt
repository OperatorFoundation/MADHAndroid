package org.operatorfoundation.madh.types

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
