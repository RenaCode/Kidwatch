package pl.renacode.kidwatch.tv

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.provider.Settings
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import java.net.Inet4Address
import java.net.NetworkInterface

/**
 * Ekran na telewizorze: czy jest uprawnienie, kod parowania, adres. Wszystko
 * inne dzieje sie w tle (KidwatchListener + Serwer).
 */
class MainActivity : Activity() {
    private lateinit var tekst: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uklad = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(96, 64, 96, 64)
            setBackgroundColor(Color.parseColor("#1F2A44"))
        }
        tekst = TextView(this).apply {
            textSize = 26f
            setTextColor(Color.WHITE)
            gravity = Gravity.CENTER
        }
        val uprawnienie = Button(this).apply {
            text = "Ustawienia dostępu do powiadomień"
            setOnClickListener {
                try {
                    startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                } catch (_: Exception) {
                    tekst.append("\n\nTen telewizor nie ma takiego ekranu — uprawnienie nadaje Kidwatch przy instalacji.")
                }
            }
        }
        val nowyKod = Button(this).apply {
            text = "Rozparuj i pokaż nowy kod"
            setOnClickListener { Parowanie(this@MainActivity).rozparuj(); odswiez() }
        }
        uklad.addView(tekst)
        uklad.addView(uprawnienie)
        uklad.addView(nowyKod)
        setContentView(uklad)
    }

    override fun onResume() {
        super.onResume()
        odswiez()
    }

    private fun odswiez() {
        val p = Parowanie(this)
        val ok = Odczyt.stan(this).optBoolean("uprawnienie")
        tekst.text = buildString {
            append("Kidwatch TV ${BuildConfigInfo.wersja(this@MainActivity)}\n\n")
            append(if (ok) "✓ dostęp do odtwarzaczy włączony\n" else "✗ brak dostępu do odtwarzaczy\n")
            append("adres: ${adres() ?: "?"}:${Serwer.PORT}\n\n")
            if (p.sparowany) append("✓ sparowany z Kidwatch\n")
            else append("Kod parowania (wpisz w panelu Kidwatch):\n\n${p.kod()}\n")
        }
    }

    private fun adres(): String? = NetworkInterface.getNetworkInterfaces().toList()
        .flatMap { it.inetAddresses.toList() }
        .firstOrNull { !it.isLoopbackAddress && it is Inet4Address }?.hostAddress
}
