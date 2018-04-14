package org.myshelf.kosts

import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class Provider(
        val secureRandom: () -> SecureRandom,
        val keyAgreementKeyPairGenerator: () -> KeyPairGenerator,
        val keyAgreement: () -> KeyAgreement,
        val secretKeyFactory: () -> SecretKeyFactory,
        val signature: () -> Signature,
        val cipher: () -> Cipher,
        private val doKeyPair: Provider.() -> KeyPair,
        private val doKeyAgreement: Provider.(privateKey: PrivateKey, publicKey: PublicKey) -> ByteArray,
        private val doKeyAgreementKeyPair: Provider.() -> KeyPair,
        private val doSecretKey: Provider.(password: String, salt: ByteArray) -> SecretKey,
        private val doSign: Provider.(payload: ByteArray, privateKey: PrivateKey) -> ByteArray,
        private val doVerify: Provider.(payload: ByteArray, publicKey: PublicKey, toVerify: ByteArray) -> Boolean,
        private val doEncrypt: Provider.(secret: String, salt: ByteArray, iv: ByteArray, payload: ByteArray) -> ByteArray,
        private val doDecrypt: Provider.(secret: String, salt: ByteArray, iv: ByteArray, payload: ByteArray) -> ByteArray
) {
    fun genKeyPair(): KeyPair = this.doKeyPair()
    fun performKeyAgreement(privateKey: PrivateKey, publicKey: PublicKey): ByteArray = this.doKeyAgreement(privateKey, publicKey)
    fun genKeyAgreementKeyPair(): KeyPair = this.doKeyAgreementKeyPair()
    fun genSecretKey(password: String, salt: ByteArray): SecretKey = this.doSecretKey(password, salt)
    fun sign(payload: ByteArray, privateKey: PrivateKey): ByteArray = this.doSign(payload, privateKey)
    fun verify(payload: ByteArray, publicKey: PublicKey, toVerify: ByteArray): Boolean = this.doVerify(payload, publicKey, toVerify)
    fun encrypt(secret: String, salt: ByteArray, iv: ByteArray, payload: ByteArray): ByteArray = this.doEncrypt(secret, salt, iv, payload)
    fun decrypt(secret: String, salt: ByteArray, iv: ByteArray, payload: ByteArray): ByteArray = this.doDecrypt(secret, salt, iv, payload)

    fun salt(): ByteArray {
        val random = this.secureRandom()
        val salt = ByteArray(8)
        random.nextBytes(salt)
        return salt
    }

    fun generateIV(): ByteArray {
        val cipher = this.cipher()
        val random = SecureRandom()
        val iv = ByteArray(cipher.blockSize)
        random.nextBytes(iv)
        return iv
    }
}

/**
 * Provides the ability to use the builder pattern to build an own provider with own params.
 */
class ProviderBuilder() {
    constructor(init: ProviderBuilder.() -> Unit): this() {
        init()
    }

    private var secureRandom: (() -> SecureRandom)? = null
    private var keyAgreementKeyPairGenerator: (() -> KeyPairGenerator)? = null
    private var keyAgreement: (() -> KeyAgreement)? = null
    private var secretKeyFactory: (() -> SecretKeyFactory)? = null
    private var signature: (() -> Signature)? = null
    private var cipher: (() -> Cipher)? = null

    private var doKeyPair: (Provider.() -> KeyPair)? = null
    private var doKeyAgreement: (Provider.(privateKey: PrivateKey, publicKey: PublicKey) -> ByteArray)? = null
    private var doKeyAgreementKeyPair: (Provider.() -> KeyPair)? = null
    private var doSecretKey: (Provider.(password: String, salt: ByteArray) -> SecretKey)? = null
    private var doSign: (Provider.(payload: ByteArray, privateKey: PrivateKey) -> ByteArray)? = null
    private var doVerify: (Provider.(payload: ByteArray, publicKey: PublicKey, toVerify: ByteArray) -> Boolean)? = null
    private var doEncrypt: (Provider.(secret: String, salt: ByteArray, iv: ByteArray, payload: ByteArray) -> ByteArray)? = null
    private var doDecrypt: (Provider.(secret: String, salt: ByteArray, iv: ByteArray, payload: ByteArray) -> ByteArray)? = null

    fun secureRandom(secureRandom: () -> SecureRandom) {
        this.secureRandom = secureRandom
    }

    fun keyPair(doKeyPair: Provider.() -> KeyPair) {
        this.doKeyPair = doKeyPair
    }

    fun keyAgreementKeyPair(keyPairGenerator: () -> KeyPairGenerator,
                            doKeyPair: Provider.() -> KeyPair) {
        this.keyAgreementKeyPairGenerator = keyPairGenerator
        this.doKeyAgreementKeyPair = doKeyPair
    }

    fun keyAgreement(keyAgreement: () -> KeyAgreement,
                     doKeyAgreement: Provider.(privateKey: PrivateKey, publicKey: PublicKey) -> ByteArray) {
        this.keyAgreement = keyAgreement
        this.doKeyAgreement = doKeyAgreement
    }

    fun secretKeyFactory(secretKeyFactory: () -> SecretKeyFactory,
                         doSecretKey: Provider.(password: String, salt: ByteArray) -> SecretKey) {
        this.secretKeyFactory = secretKeyFactory
        this.doSecretKey = doSecretKey
    }

    fun signature(signature: () -> Signature,
                  doSign: Provider.(payload: ByteArray, privateKey: PrivateKey) -> ByteArray,
                  doVerify: Provider.(payload: ByteArray, publicKey: PublicKey, toVerify: ByteArray) -> Boolean) {
        this.signature = signature
        this.doSign = doSign
        this.doVerify = doVerify
    }

    fun cipher(cipher: () -> Cipher,
               doEncrypt: Provider.(secret: String, salt: ByteArray, iv: ByteArray, payload: ByteArray) -> ByteArray,
               doDecrypt: Provider.(secret: String, salt: ByteArray, iv: ByteArray, payload: ByteArray) -> ByteArray) {
        this.cipher = cipher
        this.doEncrypt = doEncrypt
        this.doDecrypt = doDecrypt
    }

    fun build(): Provider {
        // Initialize attributes if not already done
        this.secureRandom ?: this.secureRandom({ SecureRandom.getInstance("SHA1PRNG") })
        this.doKeyPair ?: this.keyPair({
            val keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC")
            keyPairGenerator.initialize(ECGenParameterSpec("secp521r1"), this.secureRandom())
            keyPairGenerator.generateKeyPair()
        })
        this.keyAgreementKeyPairGenerator ?: this.keyAgreementKeyPair({ KeyPairGenerator.getInstance("ECDH", "BC") }) {
            val generator = this.keyAgreementKeyPairGenerator()
            generator.initialize(ECGenParameterSpec("secp521r1"), this.secureRandom())
            generator.genKeyPair()
        }
        this.keyAgreement ?: this.keyAgreement({ KeyAgreement.getInstance("ECDH", "BC") }) {privateKey, publicKey ->
            val agreement = this.keyAgreement()
            agreement.init(privateKey)
            agreement.doPhase(publicKey, true)
            agreement.generateSecret()
        }
        this.secretKeyFactory ?: this.secretKeyFactory({ SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256") }) {password, salt ->
            val spec = PBEKeySpec(password.toCharArray(), salt, 65536, 256)
            val tmp = this.secretKeyFactory().generateSecret(spec)
            SecretKeySpec(tmp.encoded, "AES")
        }
        this.signature ?: this.signature({ Signature.getInstance("SHA256withECDSA", "BC") },{payload, privateKey ->
            val sig = this.signature()
            sig.initSign(privateKey)
            sig.update(payload)
            sig.sign()
        }, {payload, publicKey, toVerify ->
            val sig = this.signature()
            sig.initVerify(publicKey)
            sig.update(payload)
            sig.verify(toVerify)
        })
        this.cipher ?: this.cipher({ Cipher.getInstance("AES/CBC/PKCS5Padding") }, {secret, salt, iv, payload ->
            val cipher = this.cipher()
            val secretKey = this.genSecretKey(secret, salt)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(iv))
            cipher.doFinal(payload)
        }, {secret, salt, iv, payload ->
            val cipher = this.cipher()
            val secretKey = this.genSecretKey(secret, salt)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
            cipher.doFinal(payload)
        })

        return Provider(
                this.secureRandom!!,
                this.keyAgreementKeyPairGenerator!!,
                this.keyAgreement!!,
                this.secretKeyFactory!!,
                this.signature!!,
                this.cipher!!,
                this.doKeyPair!!,
                this.doKeyAgreement!!,
                this.doKeyAgreementKeyPair!!,
                this.doSecretKey!!,
                this.doSign!!,
                this.doVerify!!,
                this.doEncrypt!!,
                this.doDecrypt!!
        )
    }
}

fun provider(init: ProviderBuilder.() -> Unit): Provider = ProviderBuilder(init).build()

fun defaultProvider(): Provider = ProviderBuilder().build()