package me.pnsrc.firetunnel.data

/**
 * A release version as used in tags: `v0.12b`, `0.13`, `1.2.3-rc2`.
 *
 * Numeric parts compare numerically (missing parts are zero); a version with a
 * suffix is a pre-release and sorts before the same numbers without one
 * (`0.13b` < `0.13`); suffixes compare by letters, then by their trailing number.
 */
data class AppVersion(val numbers: List<Int>, val suffix: String) : Comparable<AppVersion> {

    companion object {
        private val PATTERN = Regex("""^[vV]?(\d+(?:\.\d+)*)-?([A-Za-z][A-Za-z0-9]*)?$""")
        private val SUFFIX = Regex("""^([A-Za-z]*)(\d*)$""")

        /** Parse [raw], or return `null` if it is not a version (e.g. `dev`). */
        fun parse(raw: String?): AppVersion? {
            val m = PATTERN.find(raw?.trim().orEmpty()) ?: return null
            val numbers = m.groupValues[1].split('.').map { it.toIntOrNull() ?: return null }
            return AppVersion(numbers, m.groupValues[2].lowercase())
        }
    }

    val isPrerelease: Boolean get() = suffix.isNotEmpty()

    override fun compareTo(other: AppVersion): Int {
        for (i in 0 until maxOf(numbers.size, other.numbers.size)) {
            val c = numbers.getOrElse(i) { 0 }.compareTo(other.numbers.getOrElse(i) { 0 })
            if (c != 0) return c
        }
        if (suffix == other.suffix) return 0
        if (suffix.isEmpty()) return 1
        if (other.suffix.isEmpty()) return -1
        val (aLetters, aNum) = splitSuffix(suffix)
        val (bLetters, bNum) = splitSuffix(other.suffix)
        return if (aLetters != bLetters) aLetters.compareTo(bLetters) else aNum.compareTo(bNum)
    }

    private fun splitSuffix(s: String): Pair<String, Int> {
        val m = SUFFIX.find(s) ?: return s to 0
        return m.groupValues[1] to (m.groupValues[2].toIntOrNull() ?: 0)
    }

    override fun toString(): String = numbers.joinToString(".") + suffix
}
