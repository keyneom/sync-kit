package com.keyneom.synckit.crypto

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Recovery codes: 128 random bits as 26 Crockford base32 characters plus 2
 * check characters that catch typos, in seven groups of four. Shared by
 * participant recovery keys and snapshot recovery locks, and identical to the
 * web package. Codes are only ever generated; parsing rejects anything else,
 * so a user-chosen passphrase can never be used.
 */
object RecoveryCodes {
    /** A new recovery code. Show it once; whoever holds it can use it. */
    fun generate(randomBytes: (Int) -> ByteArray = ::secureRandomBytes): String {
        val secret = randomBytes(SECRET_BYTES)
        try {
            return (encodeSecret(secret) + checkCharacters(secret)).chunked(4).joinToString("-")
        } finally {
            secret.fill(0)
        }
    }

    /**
     * The 16-byte secret in a recovery code. Tolerates case, spaces, and
     * hyphens, and reads I and L as 1 and O as 0. The caller zeroes the result.
     */
    fun parse(code: String): ByteArray {
        val normalized = code.uppercase()
            .replace(Regex("[\\s-]"), "")
            .replace(Regex("[IL]"), "1")
            .replace("O", "0")
        if (
            normalized.length != SECRET_CHARACTERS + CHECK_CHARACTERS ||
            !Regex("^[0-9A-HJKMNP-TV-Z]+$").matches(normalized)
        ) {
            throw SyncKitError(SyncKitErrorCode.KEY, "This is not a recovery code.")
        }
        val secret = decodeSecret(normalized.substring(0, SECRET_CHARACTERS))
        if (checkCharacters(secret) != normalized.substring(SECRET_CHARACTERS)) {
            secret.fill(0)
            throw SyncKitError(
                SyncKitErrorCode.KEY,
                "This recovery code has a typo: it does not match its check characters.",
            )
        }
        return secret
    }

    /** Whether [code] is a well-formed recovery code, for live input validation. */
    fun isWellFormed(code: String): Boolean =
        try {
            parse(code).fill(0)
            true
        } catch (_: SyncKitError) {
            false
        }

    /** 128 bits → 26 characters; the final 2 bits are zero padding. */
    private fun encodeSecret(secret: ByteArray): String {
        val output = StringBuilder()
        var buffer = 0
        var bits = 0
        for (byte in secret) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xff)
            bits += 8
            while (bits >= 5) {
                output.append(CROCKFORD[(buffer ushr (bits - 5)) and 31])
                bits -= 5
            }
            buffer = buffer and ((1 shl bits) - 1)
        }
        if (bits > 0) output.append(CROCKFORD[(buffer shl (5 - bits)) and 31])
        return output.toString()
    }

    private fun decodeSecret(characters: String): ByteArray {
        val secret = ByteArray(SECRET_BYTES)
        var buffer = 0
        var bits = 0
        var index = 0
        for (character in characters) {
            buffer = (buffer shl 5) or CROCKFORD.indexOf(character)
            bits += 5
            if (bits >= 8) {
                if (index >= SECRET_BYTES) break
                secret[index++] = ((buffer ushr (bits - 8)) and 0xff).toByte()
                bits -= 8
            }
            buffer = buffer and ((1 shl bits) - 1)
        }
        if (index != SECRET_BYTES || buffer != 0) {
            secret.fill(0)
            throw SyncKitError(SyncKitErrorCode.KEY, "This is not a recovery code.")
        }
        return secret
    }

    /** Two characters (10 bits) of SHA-256 over the secret, to catch typos. */
    private fun checkCharacters(secret: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(secret)
        val check = (((digest[0].toInt() and 0xff) shl 8) or (digest[1].toInt() and 0xff)) ushr 6
        return "${CROCKFORD[(check ushr 5) and 31]}${CROCKFORD[check and 31]}"
    }

    private fun secureRandomBytes(length: Int): ByteArray = ByteArray(length).also(SecureRandom()::nextBytes)

    private const val CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    private const val SECRET_BYTES = 16
    private const val SECRET_CHARACTERS = 26
    private const val CHECK_CHARACTERS = 2
}
