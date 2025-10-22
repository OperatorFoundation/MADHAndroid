package org.operatorfoundation.madh.types

/**
 * A Curve25519 key pair consisting of a public and private key.
 */
data class Curve25519KeyPair(
    val publicKey: Curve25519PublicKey,
    val privateKey: Curve25519PrivateKey
)
