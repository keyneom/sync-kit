package com.keyneom.synckit.parity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ParityReportTest {
    @Test
    fun writesParityReportAndCrossDecryptsPeerWhenProvided() {
        val report = ParityReport.build()
        val json = ParityReport.toJson(report)

        val output = resolveOutputFile()
        output.parentFile.mkdirs()
        output.writeText(json)

        assertEquals(1, report.version)
        assertEquals("kotlin", report.platform)
        assertTrue(report.identical.contentKeys.containsKey("easy-bc"))
        assertTrue(report.identical.encryptUncompressed.compression == null)
        assertEquals("gzip", report.peerChallenge.envelope.compression)

        val peerPath = System.getenv("PARITY_PEER_REPORT")
        if (!peerPath.isNullOrBlank()) {
            val peerJson = File(peerPath).readText()
            val fingerprint = ParityReport.decryptPeerChallenge(peerJson)
            assertEquals(report.peerChallenge.payloadFingerprint, fingerprint)
        }
    }

    private fun resolveOutputFile(): File {
        val override = System.getenv("PARITY_OUTPUT")
        if (!override.isNullOrBlank()) return File(override)
        return File("build/reports/parity-v1.json")
    }
}
