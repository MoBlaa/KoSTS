package org.myshelf.kosts

import java.security.PublicKey
import java.util.*

fun PublicKey.concat(pubKey: PublicKey): String {
    val b64This = Base64.getEncoder().encodeToString(this.encoded)
    val b64Param = Base64.getEncoder().encodeToString(pubKey.encoded)
    return b64This + b64Param
}