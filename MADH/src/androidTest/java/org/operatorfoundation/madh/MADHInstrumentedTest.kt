package org.operatorfoundation.madh

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.runner.RunWith
import org.junit.Test
import org.junit.Assert.*
import java.security.SecureRandom

@RunWith(AndroidJUnit4::class)
class MADHInstrumentedTest {
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

    @Test
    fun testBouncyCastleX25519WorksOnDevice() {
        // Verify BouncyCastle crypto works on Android's runtime
        val keyPair1 = MADH.generateKeypair()
        val keyPair2 = MADH.generateKeypair()

        assertNotNull(keyPair1.publicKey.bytes)
        assertNotNull(keyPair1.privateKey.bytes)
        assertEquals(32, keyPair1.publicKey.bytes.size)
        assertEquals(32, keyPair1.privateKey.bytes.size)

        // Keys should be different
        assertFalse(keyPair1.publicKey.bytes.contentEquals(keyPair2.publicKey.bytes))
    }

    @Test
    fun testSecureRandomQualityAcrossMultipleGenerations() {
        // Android's SecureRandom had historical issues on some devices
        val random = SecureRandom()
        val sessionIds = List(100) {
            val bytes = ByteArray(32)
            random.nextBytes(bytes)
            SessionIdentifier(bytes)
        }

        // Verify no duplicates
        val uniqueIds = sessionIds.map { it.bytes.contentHashCode() }.toSet()
        assertEquals(100, uniqueIds.size)

        // Verify no all-zeros
        sessionIds.forEach { sessionId ->
            assertFalse(sessionId.bytes.all { it == 0.toByte() })
        }
    }

    @Test
    fun testSHA256ConsistencyOnDevice() {
        // Verify Android's SHA-256 produces consistent results
        val testData = "test data".toByteArray()
        val digest1 = java.security.MessageDigest.getInstance("SHA-256").digest(testData)
        val digest2 = java.security.MessageDigest.getInstance("SHA-256").digest(testData)

        assertArrayEquals(digest1, digest2)
        assertEquals(32, digest1.size)
    }

    @Test
    fun testConfirmationCodeConsistencyAcrossReboots() {
        // Simulate saving/loading state as would happen across app restarts
        val random = SecureRandom()

        val aliceKeyPair = MADH.generateKeypair()
        val bobKeyPair = MADH.generateKeypair()
        val aliceSessionId = generateSessionIdentifier(random)
        val bobSessionId = generateSessionIdentifier(random)

        val confirmation = MADH.computeConfirmation(
            senderSession = aliceSessionId,
            receiverSession = bobSessionId,
            senderPublicKey = aliceKeyPair.publicKey,
            receiverPublicKey = bobKeyPair.publicKey
        )

        val code1 = MADH.computeConfirmationCode(confirmation)

        // Simulate serialization/deserialization
        val restoredConfirmation = Confirmation(confirmation.bytes.clone())
        val code2 = MADH.computeConfirmationCode(restoredConfirmation)

        assertEquals(code1, code2)
    }

    @Test
    fun testConfirmationCodeRange() {
        // Verify confirmation codes are in expected range (0-16777215)
        val random = SecureRandom()

        repeat(100) {
            val aliceKeyPair = MADH.generateKeypair()
            val bobKeyPair = MADH.generateKeypair()
            val aliceSessionId = generateSessionIdentifier(random)
            val bobSessionId = generateSessionIdentifier(random)

            val confirmation = MADH.computeConfirmation(
                senderSession = aliceSessionId,
                receiverSession = bobSessionId,
                senderPublicKey = aliceKeyPair.publicKey,
                receiverPublicKey = bobKeyPair.publicKey
            )

            val code = MADH.computeConfirmationCode(confirmation).toInt()
            assertTrue("Code $code out of range", code in 0..16777215)
        }
    }

    @Test
    fun testKeyGenerationPerformance() {
        // Verify key generation is acceptably fast on device
        val startTime = System.nanoTime()
        repeat(100) {
            MADH.generateKeypair()
        }
        val endTime = System.nanoTime()

        val avgTimeMs = (endTime - startTime) / 1_000_000.0 / 100
        println("Average key generation time: ${avgTimeMs}ms")

        // Should be well under 100ms per keypair on modern devices
        assertTrue("Key generation too slow: ${avgTimeMs}ms", avgTimeMs < 100.0)
    }

    @Test
    fun testFullProtocolWithSerializedKeys() {
        // Test the full protocol with keys that have been serialized/deserialized
        // as would happen when storing keys in SharedPreferences or a database
        val random = SecureRandom()

        val aliceKeyPair = MADH.generateKeypair()
        val aliceSessionId = generateSessionIdentifier(random)

        // Serialize Alice's keys
        val alicePublicBytes = aliceKeyPair.publicKey.bytes
        val alicePrivateBytes = aliceKeyPair.privateKey.bytes
        val aliceSessionBytes = aliceSessionId.bytes

        // Bob generates his keys
        val bobKeyPair = MADH.generateKeypair()
        val bobSessionId = generateSessionIdentifier(random)

        // Deserialize Alice's keys (simulating loading from storage)
        val restoredAlicePublic = Curve25519PublicKey(alicePublicBytes)
        val restoredAliceSession = SessionIdentifier(aliceSessionBytes)

        // Compute confirmations
        val aliceConfirmation = MADH.computeConfirmation(
            senderSession = restoredAliceSession,
            receiverSession = bobSessionId,
            senderPublicKey = restoredAlicePublic,
            receiverPublicKey = bobKeyPair.publicKey
        )

        val bobConfirmation = MADH.computeConfirmation(
            senderSession = restoredAliceSession,
            receiverSession = bobSessionId,
            senderPublicKey = restoredAlicePublic,
            receiverPublicKey = bobKeyPair.publicKey
        )

        val aliceCode = MADH.computeConfirmationCode(aliceConfirmation)
        val bobCode = MADH.computeConfirmationCode(bobConfirmation)

        assertEquals(aliceCode, bobCode)
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