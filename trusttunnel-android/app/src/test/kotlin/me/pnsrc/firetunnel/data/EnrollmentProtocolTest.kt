package me.pnsrc.firetunnel.data

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EnrollmentProtocolTest {

    private val enrollUrl =
        "https://hotspot.bothammer.ru/enroll/2966db97a94c3700a23b582f59388192d4544c318832b368"

    // ── parseEnrollLink ─────────────────────────────────────────────────────────

    @Test
    fun `deeplink with encoded url is decoded`() {
        val link = "firetunnel://enroll?url=https%3A%2F%2Fhotspot.bothammer.ru%2Fenroll%2F" +
            "2966db97a94c3700a23b582f59388192d4544c318832b368"
        assertEquals(enrollUrl, EnrollmentProtocol.parseEnrollLink(link))
    }

    @Test
    fun `deeplink scheme and host are case insensitive and whitespace is trimmed`() {
        val link = "  FireTunnel://ENROLL?url=https%3A%2F%2Fexample.com%2Fenroll%2Fabc\n"
        assertEquals("https://example.com/enroll/abc", EnrollmentProtocol.parseEnrollLink(link))
    }

    @Test
    fun `deeplink url parameter is found among other parameters`() {
        val link = "firetunnel://enroll?src=lk&url=https%3A%2F%2Fexample.com%2Fenroll%2Fabc&x=1"
        assertEquals("https://example.com/enroll/abc", EnrollmentProtocol.parseEnrollLink(link))
    }

    @Test
    fun `bare https link is accepted as is`() {
        assertEquals(enrollUrl, EnrollmentProtocol.parseEnrollLink(enrollUrl))
    }

    @Test
    fun `invalid links are rejected`() {
        val invalid = listOf(
            "",
            "   ",
            "not a link",
            "firetunnel://enroll",
            "firetunnel://enroll?url=",
            "firetunnel://other?url=https%3A%2F%2Fexample.com%2Fenroll%2Fabc",
            "firetunnel://enroll?url=http%3A%2F%2Fexample.com%2Fenroll%2Fabc",
            "firetunnel://enroll?url=javascript%3Aalert(1)",
            "http://example.com/enroll/abc",
            "https://example.com",
            "https://example.com/",
            "ftp://example.com/enroll/abc",
        )
        for (link in invalid) {
            assertNull("expected rejection of '$link'", EnrollmentProtocol.parseEnrollLink(link))
        }
    }

    @Test
    fun `display host hides the token`() {
        assertEquals("hotspot.bothammer.ru", EnrollmentProtocol.displayHost(enrollUrl))
    }

    // ── fingerprint / config id ─────────────────────────────────────────────────

    @Test
    fun `fingerprint is sha256 of machine id with salt`() {
        // sha256("abc:firetunnel")
        val expected = java.security.MessageDigest.getInstance("SHA-256")
            .digest("abc:firetunnel".toByteArray())
            .joinToString("") { "%02x".format(it) }
        val fp = EnrollmentProtocol.fingerprint("abc")
        assertEquals(expected, fp)
        assertEquals(64, fp.length)
        assertTrue(fp.all { it in '0'..'9' || it in 'a'..'f' })
        assertEquals(fp, EnrollmentProtocol.fingerprint("abc"))
        assertFalse(fp == EnrollmentProtocol.fingerprint("abd"))
    }

    @Test
    fun `config id is stable per link`() {
        val id = EnrollmentProtocol.configIdFor(enrollUrl)
        assertTrue(id.startsWith("enroll_"))
        assertEquals(id, EnrollmentProtocol.configIdFor(enrollUrl))
        assertFalse(id == EnrollmentProtocol.configIdFor("https://example.com/enroll/other"))
    }

    // ── request body ────────────────────────────────────────────────────────────

    @Test
    fun `request body contains all fields`() {
        val json = JSONObject(EnrollmentProtocol.buildRequestBody("f".repeat(64), "Pixel \"8\"", "ivan"))
        assertEquals("f".repeat(64), json.getString("fingerprint"))
        assertEquals("Pixel \"8\"", json.getString("name"))
        assertEquals("ivan", json.getString("user"))
    }

    @Test
    fun `request body omits blank optional fields`() {
        val json = JSONObject(EnrollmentProtocol.buildRequestBody("f".repeat(64), " ", null))
        assertTrue(json.has("fingerprint"))
        assertFalse(json.has("name"))
        assertFalse(json.has("user"))
    }

    // ── response classification ─────────────────────────────────────────────────

    @Test
    fun `200 returns config and file name`() {
        val toml = "loglevel = \"info\"\n[endpoint]\nhostname = \"fvpn.ddns.net\"\n"
        val r = EnrollmentProtocol.classifyResponse(
            200, toml, "attachment; filename=\"hotspot-ferma3.toml\""
        )
        assertEquals(EnrollResult.Success(toml.trim(), "hotspot-ferma3.toml"), r)
    }

    @Test
    fun `200 with empty body is a client error`() {
        assertTrue(EnrollmentProtocol.classifyResponse(200, "  \n", null) is EnrollResult.ClientError)
    }

    @Test
    fun `403 device_revoked wipes config`() {
        val r = EnrollmentProtocol.classifyResponse(
            403, """{"error":"device_revoked","message":"Устройство отозвано"}""", null
        )
        assertEquals(EnrollResult.Revoked(403, "device_revoked", "Устройство отозвано"), r)
    }

    @Test
    fun `403 no_access wipes config`() {
        val r = EnrollmentProtocol.classifyResponse(403, """{"error":"no_access","message":"m"}""", null)
        assertEquals(EnrollResult.Revoked(403, "no_access", "m"), r)
    }

    @Test
    fun `404 unknown_link wipes config`() {
        val r = EnrollmentProtocol.classifyResponse(404, """{"error":"unknown_link"}""", null)
        assertEquals(EnrollResult.Revoked(404, "unknown_link", null), r)
    }

    @Test
    fun `404 without json body still wipes config`() {
        val r = EnrollmentProtocol.classifyResponse(404, "<html>Not Found</html>", null)
        assertEquals(EnrollResult.Revoked(404, null, null), r)
    }

    @Test
    fun `400 is a client error with message`() {
        val r = EnrollmentProtocol.classifyResponse(400, """{"error":"bad_request","message":"bad fp"}""", null)
        assertEquals(EnrollResult.ClientError(400, "bad fp"), r)
    }

    @Test
    fun `429 is rate limited`() {
        assertEquals(EnrollResult.RateLimited, EnrollmentProtocol.classifyResponse(429, "", null))
    }

    @Test
    fun `5xx keeps config`() {
        for (code in listOf(500, 502, 503, 504)) {
            assertTrue(EnrollmentProtocol.classifyResponse(code, "", null) is EnrollResult.TemporaryFailure)
        }
    }

    // ── helpers ─────────────────────────────────────────────────────────────────

    @Test
    fun `error body parsing tolerates garbage`() {
        assertEquals(null to null, EnrollmentProtocol.parseErrorBody(""))
        assertEquals(null to null, EnrollmentProtocol.parseErrorBody("oops"))
        assertEquals(null to null, EnrollmentProtocol.parseErrorBody("""{"error":"","message":"  "}"""))
        assertEquals("e" to "m", EnrollmentProtocol.parseErrorBody("""{"error":"e","message":"m"}"""))
    }

    @Test
    fun `content disposition file name variants`() {
        assertNull(EnrollmentProtocol.fileNameFromContentDisposition(null))
        assertNull(EnrollmentProtocol.fileNameFromContentDisposition("attachment"))
        assertEquals("a.toml", EnrollmentProtocol.fileNameFromContentDisposition("attachment; filename=a.toml"))
        assertEquals("a b.toml", EnrollmentProtocol.fileNameFromContentDisposition("attachment; filename=\"a b.toml\""))
        assertEquals("x.toml", EnrollmentProtocol.fileNameFromContentDisposition("attachment; filename=\"../../x.toml\""))
    }
}
