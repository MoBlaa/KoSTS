package org.myshelf.kosts

import java.security.PublicKey

class Alice: BaseAlice() {

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
        val agreement = keyAgreement(this.keyPair.private, bobsKey)
        this.secret = agreement.generateSecret()

        // Decrypt
        val cryptor = BaseCryptor(this.secret!!, bobsSalt, bobsIV)
        val signature = cryptor.decrypt(encrBobsSignature)

        // concat the public keys ( as viewed from bob )
        val concatBob = bobsKey.concat(this.keyPair.public)
        // Verify the signature with bobs public key
        val verifier = verify(concatBob, bobsKey)
        val verified = verifier.verify(signature)

        if (!verified) {
            throw IllegalStateException("Signature couldn't be verified!")
        }

        // concat the public keys ( from alice point of view )
        val concatAlice = this.keyPair.public.concat(bobsKey)
        // Generate own Signature
        val sign = signature(concatAlice, this.keyPair.private)
        val signAlice = sign.sign()
        // Encrypt the signature
        val aliceCryptor = BaseCryptor(this.secret!!, this.ownSalt, this.ownIV)
        val encrAliceSign = aliceCryptor.encrypt(signAlice)

        return encrAliceSign
    }
}