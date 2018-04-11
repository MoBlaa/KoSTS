package org.myshelf.kosts

import java.security.KeyPair
import java.security.PublicKey
import java.util.*

abstract class IEntity {
    // Things that can be shared at the beginning
    val ownSalt: ByteArray = salt()
    val ownIV: ByteArray = generateIV()
    val keyPair: KeyPair = keyPairGenerator().genKeyPair()
    var oppositeSalt: ByteArray? = null
    var oppositeIV: ByteArray? = null

    // Things that will be generated during the algorithm
    var secret: ByteArray? = null
    var otherPub: PublicKey? = null
}

// Alice is starting the algorithm by providing a QR-Code
abstract class BaseAlice : IEntity() {
    abstract fun getInitDataAndPubKey(): InitData
    abstract fun receivePubKeyAndSign(bobsKey: PublicKey, encrBobsSignature: ByteArray, bobsSalt: ByteArray, bobsIV: ByteArray): ByteArray
}

// Bob receives the QR-Code
abstract class BaseBob : IEntity() {
    abstract fun receivePubKey(alicePubKey: PublicKey, aliceSalt: ByteArray, aliceIV: ByteArray): BobPubKeyAndSignAndCipherParams
    abstract fun receiveSignature(encrSign: ByteArray): Boolean
}

data class InitData (
        val aliceSalt: ByteArray,
        val aliceIV: ByteArray,
        val alicePubKey: PublicKey
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as InitData

        if (!Arrays.equals(aliceSalt, other.aliceSalt)) return false
        if (!Arrays.equals(aliceIV, other.aliceIV)) return false
        if (alicePubKey != other.alicePubKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = Arrays.hashCode(aliceSalt)
        result = 31 * result + Arrays.hashCode(aliceIV)
        result = 31 * result + alicePubKey.hashCode()
        return result
    }
}

data class BobPubKeyAndSignAndCipherParams(
        val pubKey: PublicKey,
        val sign: ByteArray,
        val salt: ByteArray,
        val iv: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as BobPubKeyAndSignAndCipherParams

        if (pubKey != other.pubKey) return false
        if (!Arrays.equals(sign, other.sign)) return false
        if (!Arrays.equals(salt, other.salt)) return false
        if (!Arrays.equals(iv, other.iv)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = pubKey.hashCode()
        result = 31 * result + Arrays.hashCode(sign)
        result = 31 * result + Arrays.hashCode(salt)
        result = 31 * result + Arrays.hashCode(iv)
        return result
    }
}