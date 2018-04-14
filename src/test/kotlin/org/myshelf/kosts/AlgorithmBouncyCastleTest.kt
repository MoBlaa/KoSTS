package org.myshelf.kosts

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.jupiter.api.*
import org.junit.jupiter.api.Assertions.assertTrue
import java.security.Security
import java.util.*

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AlgorithmBouncyCastleTest {
    @BeforeEach
    fun init() {
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }

    @AfterAll
    fun tearDown() {
        Security.removeProvider("BC")
    }

    @Test
    fun testWhole() {
        val alice: BaseAlice = Alice()
        val bob: BaseBob = Bob()

        val (alicePubKey, aliceSalt, aliceIV) = alice.getInitDataAndPubKey()
        printBytes("AlicePubKey", alicePubKey.encoded)
        println("public length: ${alicePubKey.encoded.size * 8}")
        printBytes("AlicePrivKey", alice.keyPair.private.encoded)
        println("private length: ${alice.keyPair.private.encoded.size * 8}")

        // Communication 1: Send Alice' public key to bob

        val (bobPubKey, bobSign, bobsSalt, bobIV) = bob.receivePubKey(alicePubKey, aliceSalt, aliceIV)
        printBytes("BobPubKey", bobPubKey.encoded)
        println("public length: ${bobPubKey.encoded.size * 8}")
        printBytes("BobPrivKey", bob.keyPair.private.encoded)
        println("private length: ${bob.keyPair.private.encoded.size * 8}")

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

        val provider = defaultProvider()
        val keyPair = provider.genKeyPair()

        println()
        println(" ========== ")
        println()
        printBytes("ECDSA public", keyPair.public.encoded)
        println("public length: ${keyPair.public.encoded.size * 8}")
        printBytes("ECDSA private", keyPair.private.encoded)
        println("private length: ${keyPair.private.encoded.size * 8}")
    }

    private fun printBytes(name: String, bytes: ByteArray) {
        println("$name: ${Base64.getEncoder().encodeToString(bytes)}")
    }
}