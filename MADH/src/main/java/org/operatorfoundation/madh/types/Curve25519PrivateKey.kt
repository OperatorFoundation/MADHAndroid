package org.operatorfoundation.madh.types

data class Curve25519PrivateKey(val bytes: ByteArray)
{
    override fun equals(other: Any?): Boolean
    {
        if (this == other) return true
        if (other !is Curve25519PrivateKey) return false

        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int
    {
        return bytes.contentHashCode()
    }
}