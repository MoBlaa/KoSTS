package org.myshelf.kosts

import java.security.PublicKey

class Bob : BaseBob() {
    override fun receivePubKey(alicePubKey: PublicKey, aliceSalt: ByteArray, aliceIV: ByteArray): BobPubKeyAndSignAndCipherParams {
        // Save alicePubKey
        this.otherPub = alicePubKey
        this.oppositeSalt = aliceSalt
        this.oppositeIV = aliceIV

        // Generate Secret
        val agreement = keyAgreement(this.keyPair.private, alicePubKey)
        val secret = agreement.generateSecret()
        this.secret = secret

        // Generate Signature
        val concat = this.keyPair.public.concat(alicePubKey)
        val sign = signature(concat, this.keyPair.private)
        val signature = sign.sign()

        // Encrypt
        val cryptor = BaseCryptor(secret, this.ownSalt, this.ownIV)
        val encrBobSign = cryptor.encrypt(signature)

        return BobPubKeyAndSignAndCipherParams(this.keyPair.public, encrBobSign, this.ownSalt, this.ownIV)
    }

    override fun receiveSignature(encrSign: ByteArray): Boolean {
        // Decrypt
        val aliceCryptor = BaseCryptor(this.secret!!, this.oppositeSalt!!, this.oppositeIV!!)
        val decrypted = aliceCryptor.decrypt(encrSign)

        // Verify Signature
        val concatAlice = this.otherPub!!.concat(this.keyPair.public)

        val verifier = verify(concatAlice, this.otherPub!!)
        return verifier.verify(decrypted)
    }
}