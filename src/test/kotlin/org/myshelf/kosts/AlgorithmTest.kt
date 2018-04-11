package org.myshelf.kosts

import org.bouncycastle.jce.provider.BouncyCastleProvider
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
        val alice: IAlice = Alice()
        val bob: IBob = Bob()

        val alicePubKey = alice.generatePublicKey()
        printBytes("AlicePubKey", alicePubKey.encoded)
        printBytes("AlicePrivKey", alice.keyPair.get().private.encoded)

        // Communication 1: Send Alice' public key to bob

        val (bobPubKey, bobSign, bobsSalt, bobIV) = bob.receivePubKey(alicePubKey)
        printBytes("BobPubKey", bobPubKey.encoded)
        printBytes("BobPrivKey", bob.keyPair.get().private.encoded)

        // Communication 2: Send Bobs public key, encrypted Signature and encryption Params to Alice

        val (aliceSign, aliceSalt, aliceIV) = alice.receivePubKeyAndSign(bobPubKey, bobSign, bobsSalt, bobIV)

        println()
        println(" ========== Secrets ==========")
        printBytes("AliceSecret", alice.secret.get())
        println("Alice Secret-Size: ${alice.secret.get().size * 8}")
        printBytes("BobSecret", bob.secret.get())
        println("Bob Secret-Size: ${bob.secret.get().size * 8}")

        // Communication 3: Send Alice encrypted signature to bob

        val verified = bob.receiveSignature(aliceSign, aliceSalt, aliceIV)

        assert(verified)
    }

    private fun printBytes(name: String, bytes: ByteArray) {
        println("$name: ${Base64.getEncoder().encodeToString(bytes)}")
    }
}