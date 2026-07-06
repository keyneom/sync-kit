package com.keyneom.synckit.core

enum class SyncKitErrorCode {
    AUTHORIZATION,
    COMPATIBILITY,
    CONFIGURATION,
    CONFLICT,
    CRYPTO,
    DECOMPRESSION,
    KEY,
    NOT_FOUND,
    STATE,
    NETWORK,
}

class SyncKitError(
    val code: SyncKitErrorCode,
    message: String,
    cause: Throwable? = null,
    val httpStatus: Int? = null,
) : Exception(message, cause)
