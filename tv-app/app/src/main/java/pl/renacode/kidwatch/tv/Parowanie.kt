package pl.renacode.kidwatch.tv

import android.content.Context
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Parowanie z Kidwatch: telewizor pokazuje 6 cyfr, panel Kidwatch je wysyla
 * (POST /paruj), w odpowiedzi dostaje dlugi token do GET /stan.
 *
 * Kod zmienia sie po kazdym parowaniu i po 5 blednych probach - zgadywanie
 * 6 cyfr z sieci domowej konczy sie po pieciu strzalach.
 */
class Parowanie(ctx: Context) {
    private val prefs = ctx.getSharedPreferences("parowanie", Context.MODE_PRIVATE)
    private val los = SecureRandom()

    @Synchronized
    fun kod(): String = prefs.getString("kod", null) ?: nowyKod()

    @Synchronized
    fun nowyKod(): String {
        val kod = "%06d".format(los.nextInt(1_000_000))
        prefs.edit().putString("kod", kod).putInt("bledy", 0).apply()
        return kod
    }

    val sparowany: Boolean
        get() = prefs.getString("token", null) != null

    /** Token przy poprawnym kodzie, null przy blednym. */
    @Synchronized
    fun paruj(kod: String): String? {
        if (!MessageDigest.isEqual(kod.trim().toByteArray(), kod().toByteArray())) {
            val bledy = prefs.getInt("bledy", 0) + 1
            if (bledy >= 5) nowyKod() else prefs.edit().putInt("bledy", bledy).apply()
            return null
        }
        val bajty = ByteArray(32).also(los::nextBytes)
        val token = bajty.joinToString("") { "%02x".format(it) }
        prefs.edit().putString("token", token).apply()
        nowyKod()
        return token
    }

    fun tokenOk(naglowek: String?): Boolean {
        val token = prefs.getString("token", null) ?: return false
        val podany = naglowek?.removePrefix("Bearer ")?.trim() ?: return false
        return MessageDigest.isEqual(podany.toByteArray(), token.toByteArray())
    }

    @Synchronized
    fun rozparuj() {
        prefs.edit().remove("token").apply()
        nowyKod()
    }
}
