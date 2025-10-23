package org.operatorfoundation.madh

data class Curve25519PublicKey(val bytes: ByteArray)
{
    override fun equals(other: Any?): Boolean
    {
        if (this === other) return true
        if (other !is Curve25519PublicKey) return false

        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }
}
