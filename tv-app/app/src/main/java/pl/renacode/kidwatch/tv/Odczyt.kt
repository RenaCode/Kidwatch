package pl.renacode.kidwatch.tv

import android.content.ComponentName
import android.content.Context
import android.media.MediaMetadata
import android.media.session.MediaSessionManager
import android.os.PowerManager
import org.json.JSONArray
import org.json.JSONObject

/**
 * Stan telewizora w tym samym ksztalcie, ktory Kidwatch skladal z
 * `dumpsys media_session` przez ADB: lista sesji odtwarzaczy (pakiet, stan
 * PlaybackState, tytul, podtytul) i to, czy ekran nie spi.
 *
 * Czytany NA ZADANIE, przy kazdym GET /stan - bez wlasnej pamieci stanu,
 * ktora moglaby sie rozjechac z systemem.
 */
object Odczyt {
    fun stan(ctx: Context): JSONObject {
        val pm = ctx.getSystemService(PowerManager::class.java)
        val out = JSONObject()
            .put("wersja", BuildConfigInfo.wersja(ctx))
            .put("czas", System.currentTimeMillis())
            .put("ekran", pm?.isInteractive ?: false)
        val sesje = JSONArray()
        try {
            val msm = ctx.getSystemService(MediaSessionManager::class.java)
            val nasluch = ComponentName(ctx, KidwatchListener::class.java)
            for (c in msm.getActiveSessions(nasluch)) {
                val m = c.metadata
                val desc = m?.description
                sesje.put(
                    JSONObject()
                        .put("pakiet", c.packageName)
                        .put("stan", c.playbackState?.state ?: JSONObject.NULL)
                        .put("tytul", tekst(m?.getString(MediaMetadata.METADATA_KEY_TITLE) ?: desc?.title))
                        .put("podtytul", tekst(m?.getString(MediaMetadata.METADATA_KEY_ARTIST) ?: desc?.subtitle))
                        .put("opis", tekst(desc?.description))
                )
            }
            out.put("uprawnienie", true)
        } catch (e: SecurityException) {
            // Nasluchiwacz nie jest wlaczony - patrz MainActivity.
            out.put("uprawnienie", false)
        }
        return out.put("sesje", sesje)
    }

    private fun tekst(v: CharSequence?): Any =
        v?.toString()?.trim()?.takeIf { it.isNotEmpty() } ?: JSONObject.NULL
}

object BuildConfigInfo {
    fun wersja(ctx: Context): String =
        ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName ?: "?"
}
