package org.myshelf.kosts

import java.security.KeyPair
import java.security.PublicKey
import java.util.*
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher

interface IEntity {
    val keyPair: AtomicReference<KeyPair>
    val secret: AtomicReference<ByteArray>
    val otherPub: AtomicReference<PublicKey>
}

interface IAlice : IEntity {
    fun generatePublicKey(): PublicKey
    fun receivePubKeyAndSign(bobsKey: PublicKey, encrBobsSignature: ByteArray, bobsSalt: ByteArray, cipherIV: ByteArray): AliceSignAndCipherParams
}

interface IBob : IEntity {
    fun receivePubKey(alicePubKey: PublicKey): BobPubKeyAndSignAndCipherParams
    fun receiveSignature(encrSign: ByteArray, salt: ByteArray, iv: ByteArray): Boolean
}

data class AliceSignAndCipherParams(
        val sign: ByteArray,
        val salt: ByteArray,
        val iv: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AliceSignAndCipherParams

        if (!Arrays.equals(sign, other.sign)) return false
        if (!Arrays.equals(salt, other.salt)) return false
        if (!Arrays.equals(iv, other.iv)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = Arrays.hashCode(sign)
        result = 31 * result + Arrays.hashCode(salt)
        result = 31 * result + Arrays.hashCode(iv)
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