package org.myshelf.kosts

import java.security.PublicKey

class Bob(provider: Provider = defaultProvider()) : BaseBob(provider) {
    override fun receivePubKey(alicePubKey: PublicKey, aliceSalt: ByteArray, aliceIV: ByteArray): BobPubKeyAndSignAndCipherParams {
        // Save alicePubKey
        this.otherPub = alicePubKey
        this.oppositeSalt = aliceSalt
        this.oppositeIV = aliceIV

        // Generate Secret
        this.secret = this.provider.doKeyAgreement(this.provider, this.keyPair.private, alicePubKey)

        // Generate Signature
        val concat = this.keyPair.public.concat(alicePubKey)
        val signature = this.provider.doSign(this.provider, concat.toByteArray(CHARSET), this.keyPair.private)

        // Encrypt
        val encrBobSign = this.provider.doEncrypt(this.provider, String(secret!!, CHARSET), this.ownSalt, this.ownIV, signature)

        return BobPubKeyAndSignAndCipherParams(this.keyPair.public, encrBobSign, this.ownSalt, this.ownIV)
    }

    override fun receiveSignature(encrSign: ByteArray): Boolean {
        // Decrypt
        val decrypted = this.provider.doDecrypt(this.provider, String(secret!!, CHARSET), this.oppositeSalt!!, this.oppositeIV!!, encrSign)

        // Verify Signature
        val concatAlice = this.otherPub!!.concat(this.keyPair.public)

        return this.provider.doVerify(this.provider, concatAlice.toByteArray(CHARSET), this.otherPub!!, decrypted)
    }
}