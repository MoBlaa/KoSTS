package org.myshelf.kosts

import java.security.KeyPair
import java.security.PublicKey
import java.util.concurrent.atomic.AtomicReference

class Alice(
        override val keyPair: AtomicReference<KeyPair> = AtomicReference(),
        override val secret: AtomicReference<ByteArray> = AtomicReference(),
        override val otherPub: AtomicReference<PublicKey> = AtomicReference()
) : IAlice {

    override fun generatePublicKey(): PublicKey {
        val gen = keyPairGenerator()
        val keyPair = gen.generateKeyPair()
        this.keyPair.set(keyPair)
        return keyPair.public
    }

    @Throws(IllegalStateException::class)
    override fun receivePubKeyAndSign(bobsKey: PublicKey, encrBobsSignature: ByteArray, bobsSalt: ByteArray, cipherIV: ByteArray): AliceSignAndCipherParams {
        // save public key of opposite
        this.otherPub.set(bobsKey)

        // Generate Secret
        val agreement = keyAgreement(this.keyPair.get().private, bobsKey)
        val secret = agreement.generateSecret()
        this.secret.set(secret)

        // Decrypt
        val cryptor = BaseCryptor(secret, bobsSalt)
        val signature = cryptor.decrypt(encrBobsSignature, cipherIV)

        // concat the public keys ( as viewed from bob )
        val concatBob = bobsKey.concat(this.keyPair.get().public)
        // Verify the signature with bobs public key
        val verifier = verify(concatBob, bobsKey)
        val verified = verifier.verify(signature)

        if (!verified) {
            throw IllegalStateException("Signature couldn't be verified!")
        }

        // concat the public keys ( from alice point of view )
        val concatAlice = this.keyPair.get().public.concat(bobsKey)
        // Generate own Signature
        val sign = signature(concatAlice, this.keyPair.get().private)
        val signAlice = sign.sign()
        // Encrypt the signature
        val aliceSalt = salt()
        val aliceCryptor = BaseCryptor(secret, aliceSalt)
        val (encrAliceSign, aliceIV) = aliceCryptor.encrypt(signAlice)

        return AliceSignAndCipherParams(encrAliceSign, aliceSalt, aliceIV)
    }
}