package org.operatorfoundation.madh

import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * MA-DH (Manually Authenticated Diffie-Hellman) implementation for secure key exchange
 * with out-of-band confirmation.
 */
object MADH {
    /**
     * Generates a new Curve25519 key pair for the MA-DH protocol.
     *
     * @return A new Curve25519KeyPair containing public and private keys
     */
    fun generateKeypair(): Curve25519KeyPair {
        val generator = X25519KeyPairGenerator()
        generator.init(X25519KeyGenerationParameters(SecureRandom()))

        val keyPair: AsymmetricCipherKeyPair = generator.generateKeyPair()

        val privateKeyParams = keyPair.private as X25519PrivateKeyParameters
        val publicKeyParams = keyPair.public as X25519PublicKeyParameters

        val privateKey = Curve25519PrivateKey(privateKeyParams.encoded)
        val publicKey = Curve25519PublicKey(publicKeyParams.encoded)

        return Curve25519KeyPair(publicKey, privateKey)
    }

    /**
     * Computes a SHA256 commitment hash of a Curve25519 public key.
     * This commitment can be shared before revealing the actual public key.
     *
     * @param identifier The Curve25519 public key to commit to
     * @return The SHA256 hash of the public key bytes
     */
    fun computePublicKeyCommitment(identifier: Curve25519PublicKey): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(identifier.bytes)
    }

    /**
     * Computes the confirmation value from session identifiers and public keys.
     * This value is used to derive the confirmation code for out-of-band verification.
     *
     * The computation proceeds as follows:
     * 1. Hash each input separately: H(senderSession), H(receiverSession), H(senderPublicKey), H(receiverPublicKey)
     * 2. Concatenate all four hashes
     * 3. Hash the concatenation to produce the final confirmation value
     *
     * @param senderSession The sender's session identifier
     * @param receiverSession The receiver's session identifier
     * @param senderPublicKey The sender's Curve25519 public key
     * @param receiverPublicKey The receiver's Curve25519 public key
     * @return A Confirmation value derived from the hashed inputs
     */
    fun computeConfirmation(
        senderSession: SessionIdentifier,
        receiverSession: SessionIdentifier,
        senderPublicKey: Curve25519PublicKey,
        receiverPublicKey: Curve25519PublicKey
    ): Confirmation {
        val digest = MessageDigest.getInstance("SHA-256")

        // Hash each input separately
        val senderSessionHash = digest.digest(senderSession.bytes)
        digest.reset()

        val receiverSessionHash = digest.digest(receiverSession.bytes)
        digest.reset()

        val senderPublicKeyHash = digest.digest(senderPublicKey.bytes)
        digest.reset()

        val receiverPublicKeyHash = digest.digest(receiverPublicKey.bytes)
        digest.reset()

        // Concatenate all hashes
        val concatenated = senderSessionHash + receiverSessionHash +
                senderPublicKeyHash + receiverPublicKeyHash

        // Hash the concatenation
        val finalHash = digest.digest(concatenated)

        return Confirmation(finalHash)
    }

    /**
     * Computes a human-readable confirmation code from a confirmation value.
     * This code should be compared out-of-band (e.g., verbally over phone) with the
     * remote party to verify the key exchange.
     *
     * Takes the first 24 bits (3 bytes) of the confirmation and converts them to
     * a decimal string representation.
     *
     * @param confirmation The confirmation value to convert
     * @return A decimal confirmation code string (0-16777215)
     */
    fun computeConfirmationCode(confirmation: Confirmation): String {
        // Take the first 3 bytes (24 bits)
        val byte1 = confirmation.bytes[0].toInt() and 0xFF
        val byte2 = confirmation.bytes[1].toInt() and 0xFF
        val byte3 = confirmation.bytes[2].toInt() and 0xFF

        // Combine into a 24-bit integer
        val value = (byte1 shl 16) or (byte2 shl 8) or byte3

        return value.toString()
    }
}