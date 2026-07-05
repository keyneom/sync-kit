package com.keyneom.synckit.crypto

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull

/**
 * Canonical JSON matching web [canonical.ts] and Java [SharingFixtureVerifier].
 * Object keys are sorted by UTF-16 code unit order; undefined fields are omitted.
 */
object CanonicalJson {
    fun encode(value: JsonElement): String = when (value) {
        is JsonNull -> "null"
        is JsonPrimitive -> encodePrimitive(value)
        is JsonArray -> "[" + value.joinToString(",") { encode(it) } + "]"
        is JsonObject -> "{" + value.entries
            .sortedWith { left, right -> compareUtf16CodeUnits(left.key, right.key) }
            .joinToString(",") { (key, child) -> quote(key) + ":" + encode(child) } + "}"
    }

    fun encodeAad(value: JsonElement): ByteArray =
        encode(value).toByteArray(Charsets.UTF_8)

    /**
     * Compares strings by UTF-16 code units (matches Java [String.compareTo]).
     */
    fun compareUtf16CodeUnits(left: String, right: String): Int =
        left.compareTo(right)

    private fun encodePrimitive(value: JsonPrimitive): String {
        if (value is JsonNull) return "null"
        value.booleanOrNull?.let { return it.toString() }
        value.longOrNull?.let { return it.toString() }
        value.doubleOrNull?.let { number ->
            if (!number.isFinite()) {
                throw SyncKitError(
                    SyncKitErrorCode.COMPATIBILITY,
                    "Canonical JSON does not support non-finite numbers.",
                )
            }
            return number.toString()
        }
        return quote(value.content)
    }

    private fun quote(value: String): String {
        val result = StringBuilder("\"")
        for (character in value) {
            when (character) {
                '"' -> result.append("\\\"")
                '\\' -> result.append("\\\\")
                '\b' -> result.append("\\b")
                '\u000C' -> result.append("\\f")
                '\n' -> result.append("\\n")
                '\r' -> result.append("\\r")
                '\t' -> result.append("\\t")
                else -> {
                    if (character.code < 0x20) {
                        result.append(String.format("\\u%04x", character.code))
                    } else {
                        result.append(character)
                    }
                }
            }
        }
        return result.append('"').toString()
    }
}
