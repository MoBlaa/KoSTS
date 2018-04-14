package org.myshelf.kosts

import org.bouncycastle.crypto.util.PublicKeyFactory
import java.nio.charset.Charset
import java.security.KeyPair
import java.security.PublicKey
import java.util.*

val CHARSET = Charset.forName("UTF-8")
const val SEPARATOR = "||"

class DecodeException(mssg: String): Exception(mssg)

open class IEntity(protected val provider: Provider) {
    // Things that can be shared at the beginning
    var ownSalt: ByteArray = provider.salt()
    var ownIV: ByteArray = provider.generateIV()
    var keyPair: KeyPair = provider.genKeyAgreementKeyPair()
    var oppositeSalt: ByteArray? = null
    var oppositeIV: ByteArray? = null

    // Things that will be generated during the algorithm
    var secret: ByteArray? = null
    var otherPub: PublicKey? = null

    fun reinit() {
        this.ownSalt = this.provider.salt()
        this.ownIV = this.provider.generateIV()
        this.keyPair = this.provider.genKeyAgreementKeyPair()
    }

    protected fun encode(payload: ByteArray): String = Base64.getEncoder().encodeToString(payload)
    protected fun encode(vararg payload: ByteArray): String = payload.joinToString(separator = SEPARATOR) { encode(it) }
    protected fun encode(payload: List<ByteArray>): String = payload.joinToString(separator = SEPARATOR) { encode(it) }
    protected fun decode(encoded: String): ByteArray = Base64.getDecoder().decode(encoded)
    protected fun decodeToByteArray(encoded: String): List<ByteArray>
            = encoded.split(SEPARATOR).map { Base64.getDecoder().decode(it) }
}

// Alice is starting the algorithm by providing a QR-Code
abstract class BaseAlice(provider: Provider) : IEntity(provider) {
    abstract fun getInitDataAndPubKey(): InitData
    fun getInitDataAndPubKeyEncoded(): String {
        val data = this.getInitDataAndPubKey()
        return encode(data.alicePubKey.encoded, data.aliceSalt, data.aliceIV)
    }

    abstract fun receivePubKeyAndSign(bobsKey: PublicKey, encrBobsSignature: ByteArray, bobsSalt: ByteArray, bobsIV: ByteArray): ByteArray
    fun receivePubKeyAndSignEncoded(encoded: String): String {
        val (bobsKey, encrBobsSignature, bobsSalt, bobsIV) = this.decodeBobsData(encoded)
        val data = this.receivePubKeyAndSign(bobsKey, encrBobsSignature, bobsSalt, bobsIV)
        return encode(data)
    }
    private fun decodeBobsData(encode: String): BobPubKeyAndSignAndCipherParams {
        val decodedList = this.decodeToByteArray(encode)
        val result: BobPubKeyAndSignAndCipherParams

        if (decodedList.size == 4) {
            val pubKey = super.provider.decodePubKey(decodedList[0])
            val sign = decodedList[1]
            val salt = decodedList[2]
            val iv = decodedList[3]

            result = BobPubKeyAndSignAndCipherParams(pubKey, sign, salt, iv)
        } else {
            throw DecodeException("Invalid number of parameters from bob: ${decodedList.size}")
        }

        return result
    }
}

// Bob receives the QR-Code
abstract class BaseBob(provider: Provider) : IEntity(provider) {

    abstract fun receivePubKey(alicePubKey: PublicKey, aliceSalt: ByteArray, aliceIV: ByteArray): BobPubKeyAndSignAndCipherParams
    fun receivePubKeyEncoded(encoded: String): String {
        val (alicePubKey, aliceSalt, aliceIV) = this.decodeAliceData(encoded)
        val data = this.receivePubKey(alicePubKey, aliceSalt, aliceIV)
        return encode(data.asList())
    }
    private fun decodeAliceData(encoded: String): InitData {
        val list = this.decodeToByteArray(encoded)
        val result: InitData

        if (list.size == 3) {
            val pubKey = super.provider.decodePubKey(list[0])
            val salt = list[1]
            val iv = list[2]

            result = InitData(pubKey, salt, iv)
        } else {
            throw DecodeException("Invalid number of parameters from alice: ${list.size}")
        }

        return result
    }

    abstract fun receiveSignature(encrSign: ByteArray): Boolean
    private fun receiveSignatureEncoded(encoded: String): Boolean = this.receiveSignature(this.decode(encoded))
}

data class InitData (
        val alicePubKey: PublicKey,
        val aliceSalt: ByteArray,
        val aliceIV: ByteArray
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

    fun asList(): List<ByteArray> = Arrays.asList(this.pubKey.encoded, this.sign, this.salt, this.iv)
}