package me.pnsrc.firetunnel.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateTest {

    private fun v(s: String) = AppVersion.parse(s)!!

    // ── AppVersion ──────────────────────────────────────────────────────────────

    @Test
    fun `parse versions`() {
        assertEquals(AppVersion(listOf(0, 12), "b"), AppVersion.parse("v0.12b"))
        assertEquals(AppVersion(listOf(1, 2, 3), "rc2"), AppVersion.parse("1.2.3-rc2"))
        assertEquals(AppVersion(listOf(1, 0, 0), ""), AppVersion.parse("1.0.0"))
        assertNull(AppVersion.parse("dev"))
        assertNull(AppVersion.parse(""))
        assertNull(AppVersion.parse(null))
        assertNull(AppVersion.parse("v1.x"))
    }

    @Test
    fun `compare versions`() {
        assertTrue(v("v0.13b") > v("v0.12b"))
        assertTrue(v("0.13") > v("0.13b"))
        assertTrue(v("0.13b2") > v("0.13b"))
        assertTrue(v("0.13rc") > v("0.13b9"))
        assertTrue(v("1.0") > v("0.99"))
        assertTrue(v("0.12.1b") > v("0.12b"))
        assertEquals(0, v("0.12").compareTo(v("0.12.0")))
        assertTrue(v("0.12b").isPrerelease)
        assertFalse(v("0.12").isPrerelease)
    }

    // ── ReleaseParser ───────────────────────────────────────────────────────────

    private val digest = "a".repeat(64)
    private val releases = """
        [
          {"tag_name":"v0.14b","name":"Draft","draft":true,"assets":[{"name":"FireTunnel-0.14b.apk","browser_download_url":"https://x/y.apk"}]},
          {"tag_name":"v0.13b","name":"FireTunnel v0.13b","draft":false,"body":" Notes ","html_url":"https://github.com/o/r/releases/tag/v0.13b",
           "assets":[{"name":"TrustTunnel-0.13b-linux.tar.gz","browser_download_url":"https://x/l.tgz"},
                     {"name":"FireTunnel-0.13b.apk","browser_download_url":"https://x/a.apk","size":1234,"digest":"sha256:$digest"}]},
          {"tag_name":"v0.12b","name":"","draft":false,"assets":[{"name":"FireTunnel-0.12b.apk","browser_download_url":"https://x/b.apk"}]},
          {"tag_name":"v0.20b","name":"Desktop only","draft":false,"assets":[{"name":"TrustTunnel-0.20b.zip","browser_download_url":"https://x/w.zip"}]}
        ]
    """.trimIndent()

    @Test
    fun `newest apk release is picked`() {
        val r = ReleaseParser.newestUpdate(releases, v("0.12b"))!!
        assertEquals("v0.13b", r.tag)
        assertEquals("FireTunnel v0.13b", r.title)
        assertEquals("Notes", r.notes)
        assertEquals("FireTunnel-0.13b.apk", r.apkName)
        assertEquals("https://x/a.apk", r.apkUrl)
        assertEquals(1234L, r.apkSize)
        assertEquals(digest, r.apkSha256)
    }

    @Test
    fun `no update when current is newest`() {
        assertNull(ReleaseParser.newestUpdate(releases, v("0.13b")))
        assertNull(ReleaseParser.newestUpdate(releases, v("0.13")))
    }

    @Test
    fun `unknown current version gets the newest`() {
        assertEquals("v0.13b", ReleaseParser.newestUpdate(releases, null)?.tag)
    }

    @Test
    fun `malformed input and assets`() {
        assertNull(ReleaseParser.newestUpdate("not json", null))
        assertNull(ReleaseParser.newestUpdate("{}", null))
        val insecure = """[{"tag_name":"v1.0","assets":[{"name":"a.apk","browser_download_url":"http://x/a.apk"}]}]"""
        assertNull(ReleaseParser.newestUpdate(insecure, null))
        val badDigest = """[{"tag_name":"v1.0","assets":[{"name":"a.apk","browser_download_url":"https://x/a.apk","digest":"sha1:abc"}]}]"""
        assertNull(ReleaseParser.newestUpdate(badDigest, null)!!.apkSha256)
    }
}
