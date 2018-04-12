package org.myshelf.kosts

import java.security.PublicKey

class Alice(provider: Provider = defaultProvider()) : BaseAlice(provider) {

    override fun getInitDataAndPubKey(): InitData {
        return InitData(this.ownSalt, this.ownIV, this.keyPair.public)
    }

    @Throws(IllegalStateException::class)
    override fun receivePubKeyAndSign(bobsKey: PublicKey, encrBobsSignature: ByteArray, bobsSalt: ByteArray, bobsIV: ByteArray): ByteArray {
        // save public key of opposite
        this.otherPub = bobsKey
        this.oppositeIV = bobsIV
        this.oppositeSalt = bobsSalt

        // Generate Secret
        this.secret = this.provider.doKeyAgreement(this.provider, this.keyPair.private, bobsKey)

        // Decrypt
        val signature = this.provider.doDecrypt(this.provider, String(secret!!, CHARSET), bobsSalt, bobsIV, encrBobsSignature)

        // concat the public keys ( as viewed from bob )
        val concatBob = bobsKey.concat(this.keyPair.public)
        // Verify the signature with bobs public key
        val verified = this.provider.doVerify(this.provider, concatBob.toByteArray(CHARSET), bobsKey, signature)

        if (!verified) {
            throw IllegalStateException("Signature couldn't be verified!")
        }

        // concat the public keys ( from alice point of view )
        val concatAlice = this.keyPair.public.concat(bobsKey)
        // Generate own Signature
        val signAlice = this.provider.doSign(this.provider, concatAlice.toByteArray(CHARSET), this.keyPair.private)
        // Encrypt the signature
        val encrAliceSign = this.provider.doEncrypt(this.provider, String(secret!!, CHARSET), this.ownSalt, this.ownIV, signAlice)

        return encrAliceSign
    }
}