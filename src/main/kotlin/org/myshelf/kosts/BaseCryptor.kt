package org.myshelf.kosts

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class BaseCryptor(secret: ByteArray, salt: ByteArray) {
    val secretKey: SecretKey = toSecret(String(secret, CHARSET), salt)

    fun encrypt(payload: ByteArray): Pair<ByteArray, ByteArray> {
        val cipher = cipher()
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val params = cipher.parameters
        return Pair(
                cipher.doFinal(payload),
                params.getParameterSpec(IvParameterSpec::class.java).iv
        )
    }

    fun decrypt(payload: ByteArray, iv: ByteArray): ByteArray {
        val cipher = cipher()
        cipher.init(Cipher.DECRYPT_MODE, this.secretKey, IvParameterSpec(iv))
        return cipher.doFinal(payload)
    }
}