package com.keyneom.synckit.crypto

import kotlinx.serialization.json.Json

object SyncKitJson {
    val instance: Json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        explicitNulls = false
    }
}
