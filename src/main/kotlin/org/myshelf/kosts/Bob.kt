package org.myshelf.kosts

import java.security.KeyPair
import java.security.PublicKey
import java.util.concurrent.atomic.AtomicReference

class Bob(
        override val keyPair: AtomicReference<KeyPair> = AtomicReference(),
        override val secret: AtomicReference<ByteArray> = AtomicReference(),
        override val otherPub: AtomicReference<PublicKey> = AtomicReference()
) : IBob {
    override fun receivePubKey(alicePubKey: PublicKey): BobPubKeyAndSignAndCipherParams {
        // Save pubKey
        this.otherPub.set(alicePubKey)

        // Generate own KeyPair
        val keyPairGenerator = keyPairGenerator()
        val bobsKeyPair = keyPairGenerator.genKeyPair()
        this.keyPair.set(bobsKeyPair)

        // Generate Secret
        val agreement = keyAgreement(bobsKeyPair.private, alicePubKey)
        val secret = agreement.generateSecret()
        this.secret.set(secret)

        // Generate Signature
        val concat = bobsKeyPair.public.concat(alicePubKey)
        val sign = signature(concat, bobsKeyPair.private)
        val signature = sign.sign()

        // Encrypt
        val salt = salt()
        val cryptor = BaseCryptor(secret, salt)
        val (encrBobSign, bobIV) = cryptor.encrypt(signature)

        return BobPubKeyAndSignAndCipherParams(bobsKeyPair.public, encrBobSign, salt, bobIV)
    }

    override fun receiveSignature(encrSign: ByteArray, salt: ByteArray, iv: ByteArray): Boolean {
        // Decrypt
        val aliceCryptor = BaseCryptor(this.secret.get(), salt)
        val decrypted = aliceCryptor.decrypt(encrSign, iv)

        // Verify Signature
        val concatAlice = this.otherPub.get().concat(this.keyPair.get().public)

        val verifier = verify(concatAlice, this.otherPub.get())
        return verifier.verify(decrypted)
    }
}