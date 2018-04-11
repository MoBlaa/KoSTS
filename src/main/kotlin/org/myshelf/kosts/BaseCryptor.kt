package org.myshelf.kosts

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class BaseCryptor(secret: ByteArray, salt: ByteArray, val iv: ByteArray) {
    val secretKey: SecretKey = toSecret(String(secret, CHARSET), salt)
    val cipher: Cipher = cipher()

    fun encrypt(payload: ByteArray): ByteArray {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(iv))
        return cipher.doFinal(payload)
    }

    fun decrypt(payload: ByteArray): ByteArray {
        val cipher = cipher()
        cipher.init(Cipher.DECRYPT_MODE, this.secretKey, IvParameterSpec(iv))
        return cipher.doFinal(payload)
    }
}