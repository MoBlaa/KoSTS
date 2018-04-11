package org.myshelf.kosts

import java.nio.charset.Charset
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

val CHARSET = Charset.forName("UTF-8")!!

fun secureRandom(): SecureRandom {
    return SecureRandom.getInstance("SHA1PRNG")
}

fun keyPairGenerator(): KeyPairGenerator {
    val keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC")
    keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"), secureRandom())
    return keyPairGenerator
}

fun keyAgreement(privateKey: PrivateKey, publicKey: PublicKey): KeyAgreement {
    val agreement = KeyAgreement.getInstance("ECDH", "BC")
    agreement.init(privateKey)
    agreement.doPhase(publicKey, true)
    return agreement
}

fun toSecret(password: String, salt: ByteArray): SecretKey {
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val spec = PBEKeySpec(password.toCharArray(), salt, 65536, 256)
    val tmp = factory.generateSecret(spec)
    return SecretKeySpec(tmp.encoded, "AES")
}

fun signature(payload: String, privateKey: PrivateKey): Signature {
    val sig = Signature.getInstance("SHA256withECDSA", "BC")
    sig.initSign(privateKey)
    sig.update(payload.toByteArray(CHARSET))
    return sig
}

fun verify(payload: String, publicKey: PublicKey): Signature {
    val sig = Signature.getInstance("SHA256withECDSA", "BC")
    sig.initVerify(publicKey)
    sig.update(payload.toByteArray(CHARSET))
    return sig
}

fun salt(): ByteArray {
    val random = secureRandom()
    val salt = ByteArray(8)
    random.nextBytes(salt)
    return salt
}

fun cipher(): Cipher {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    return cipher
}

fun PublicKey.concat(pubKey: PublicKey): String {
    val b64This = Base64.getEncoder().encodeToString(this.encoded)
    val b64Param = Base64.getEncoder().encodeToString(pubKey.encoded)
    return b64This + b64Param
}