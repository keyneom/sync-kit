package com.keyneom.synckit.crypto

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import java.util.Base64

object Base64Url {
    fun encode(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    fun decode(value: String): ByteArray =
        try {
            Base64.getUrlDecoder().decode(value)
        } catch (error: IllegalArgumentException) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The value is not valid unpadded base64url.",
                error,
            )
        }
}
