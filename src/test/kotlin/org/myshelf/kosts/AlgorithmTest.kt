package org.myshelf.kosts

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.security.Security
import java.util.*

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AlgorithmTest {
    @BeforeAll
    fun init() {
        Security.addProvider(BouncyCastleProvider())
    }

    @Test
    fun testWhole() {
        val alice: BaseAlice = Alice()
        val bob: BaseBob = Bob()

        val (aliceSalt, aliceIV, alicePubKey) = alice.getInitDataAndPubKey()
        printBytes("AlicePubKey", alicePubKey.encoded)
        printBytes("AlicePrivKey", alice.keyPair.private.encoded)

        // Communication 1: Send Alice' public key to bob

        val (bobPubKey, bobSign, bobsSalt, bobIV) = bob.receivePubKey(alicePubKey, aliceSalt, aliceIV)
        printBytes("BobPubKey", bobPubKey.encoded)
        printBytes("BobPrivKey", bob.keyPair.private.encoded)

        // Communication 2: Send Bobs public key, encrypted Signature and encryption Params to Alice

        val aliceSign = alice.receivePubKeyAndSign(bobPubKey, bobSign, bobsSalt, bobIV)

        println()
        println(" ========== Secrets ==========")
        printBytes("AliceSecret", alice.secret!!)
        println("Alice Secret-Size: ${alice.secret!!.size * 8}")
        printBytes("BobSecret", bob.secret!!)
        println("Bob Secret-Size: ${bob.secret!!.size * 8}")

        // Communication 3: Send Alice encrypted signature to bob

        val verified = bob.receiveSignature(aliceSign)

        println()
        println("Signature verified: $verified")

        assertTrue(verified)
    }

    private fun printBytes(name: String, bytes: ByteArray) {
        println("$name: ${Base64.getEncoder().encodeToString(bytes)}")
    }
}