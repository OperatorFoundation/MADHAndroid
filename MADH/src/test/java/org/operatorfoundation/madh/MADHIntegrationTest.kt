package org.operatorfoundation.madh

import org.junit.Test
import org.junit.Assert.*
import java.security.SecureRandom

class MADHIntegrationTest {

    @Test
    fun testFullMADHProtocol() {
        val random = SecureRandom()

        // Step 1: Alice generates her keypair and session identifier
        val aliceKeyPair = MADH.generateKeypair()
        val aliceSessionId = generateSessionIdentifier(random)

        // Step 2: Alice computes commitment to her public key and "sends" it to Bob
        val aliceCommitment = MADH.computePublicKeyCommitment(aliceKeyPair.publicKey)
        println("Alice's commitment: ${aliceCommitment.joinToString("") { "%02x".format(it) }}")

        // Step 3: Bob generates his keypair and session identifier
        val bobKeyPair = MADH.generateKeypair()
        val bobSessionId = generateSessionIdentifier(random)

        // Step 4: Bob "sends" his public key and session ID to Alice
        println("Bob sends his public key and session ID to Alice")

        // Step 5: Alice "sends" her public key to Bob
        println("Alice sends her public key to Bob")

        // Step 6: Alice computes confirmation (she is the sender)
        val aliceConfirmation = MADH.computeConfirmation(
            senderSession = aliceSessionId,
            receiverSession = bobSessionId,
            senderPublicKey = aliceKeyPair.publicKey,
            receiverPublicKey = bobKeyPair.publicKey
        )

        // Step 7: Bob computes confirmation (Alice is the sender, Bob is the receiver)
        val bobConfirmation = MADH.computeConfirmation(
            senderSession = aliceSessionId,  // Alice's session (she's the sender)
            receiverSession = bobSessionId,   // Bob's session (he's the receiver)
            senderPublicKey = aliceKeyPair.publicKey,  // Alice's key (she's the sender)
            receiverPublicKey = bobKeyPair.publicKey   // Bob's key (he's the receiver)
        )

        // Step 8: Both parties compute confirmation codes
        val aliceCode = MADH.computeConfirmationCode(aliceConfirmation)
        val bobCode = MADH.computeConfirmationCode(bobConfirmation)

        println("Alice's confirmation code: $aliceCode")
        println("Bob's confirmation code: $bobCode")

        // Step 9: Verify that confirmation codes match
        assertEquals("Confirmation codes should match", aliceCode, bobCode)

        // Additional verification: the confirmations themselves should match
        assertArrayEquals(
            "Raw confirmations should match",
            aliceConfirmation.bytes,
            bobConfirmation.bytes
        )

        println("✓ MA-DH protocol completed successfully!")
        println("✓ Both parties derived the same confirmation code: $aliceCode")
    }

    /**
     * Helper function to generate a unique session identifier.
     * In practice, this could be a sequential counter, UUID, or random bytes.
     */
    private fun generateSessionIdentifier(random: SecureRandom): SessionIdentifier {
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return SessionIdentifier(bytes)
    }
}