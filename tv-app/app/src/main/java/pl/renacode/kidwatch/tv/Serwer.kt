package pl.renacode.kidwatch.tv

import android.content.Context
import android.util.Log
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.InputStream
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import kotlin.concurrent.thread

/**
 * Minimalny serwer HTTP/1.0 w sieci domowej (bez bibliotek - trzy endpointy):
 *
 *   GET  /zdrowie   wersja, uprawnienie, sparowany   (bez tokenu - diagnostyka)
 *   POST /paruj     {"kod": "123456"} -> {"token": "..."}
 *   GET  /stan      Authorization: Bearer <token> -> Odczyt.stan
 *
 * Polaczenie = jedno zapytanie, potem zamkniecie. Kidwatch pyta co 30 s.
 */
class Serwer(private val ctx: Context, private val port: Int = PORT) {
    private var gniazdo: ServerSocket? = null
    private val parowanie = Parowanie(ctx)

    fun start() {
        if (gniazdo != null) return
        val s = try {
            ServerSocket(port)
        } catch (e: Exception) {
            Log.w(TAG, "port $port zajety: ${e.message}")
            return
        }
        gniazdo = s
        thread(name = "kidwatch-serwer", isDaemon = true) {
            while (!s.isClosed) {
                val k = try { s.accept() } catch (e: Exception) { break }
                thread(name = "kidwatch-zapytanie", isDaemon = true) { obsluz(k) }
            }
        }
        Log.i(TAG, "serwer na porcie $port")
    }

    fun stop() {
        gniazdo?.close()
        gniazdo = null
    }

    private fun obsluz(k: Socket) {
        k.use { sock ->
            sock.soTimeout = 5000
            try {
                val wej = BufferedInputStream(sock.getInputStream())
                val linia = czytajLinie(wej) ?: return
                val (metoda, sciezka) = linia.split(" ").let { (it.getOrNull(0) ?: "") to (it.getOrNull(1) ?: "") }
                val naglowki = mutableMapOf<String, String>()
                while (true) {
                    val l = czytajLinie(wej) ?: break
                    if (l.isEmpty()) break
                    val i = l.indexOf(':')
                    if (i > 0) naglowki[l.substring(0, i).trim().lowercase()] = l.substring(i + 1).trim()
                }
                val dl = naglowki["content-length"]?.toIntOrNull()?.coerceIn(0, 4096) ?: 0
                val cialo = ByteArray(dl).also { var n = 0; while (n < dl) { val r = wej.read(it, n, dl - n); if (r < 0) break; n += r } }
                val (kod, json) = odpowiedz(metoda, sciezka, naglowki, String(cialo))
                val bajty = json.toString().toByteArray()
                val out = sock.getOutputStream()
                out.write(("HTTP/1.0 $kod ${opis(kod)}\r\nContent-Type: application/json\r\n" +
                    "Content-Length: ${bajty.size}\r\nConnection: close\r\n\r\n").toByteArray())
                out.write(bajty)
                out.flush()
            } catch (_: SocketTimeoutException) {
            } catch (e: Exception) {
                Log.w(TAG, "zapytanie: ${e.message}")
            }
        }
    }

    internal fun odpowiedz(metoda: String, sciezka: String, naglowki: Map<String, String>,
                           cialo: String): Pair<Int, JSONObject> = when {
        metoda == "GET" && sciezka == "/zdrowie" -> 200 to JSONObject()
            .put("wersja", BuildConfigInfo.wersja(ctx))
            .put("uprawnienie", Odczyt.stan(ctx).optBoolean("uprawnienie"))
            .put("sparowany", parowanie.sparowany)
        metoda == "POST" && sciezka == "/paruj" -> {
            val kod = try { JSONObject(cialo).optString("kod") } catch (_: Exception) { "" }
            val token = parowanie.paruj(kod)
            if (token == null) 403 to JSONObject().put("blad", "zly kod")
            else 200 to JSONObject().put("token", token)
        }
        metoda == "GET" && sciezka == "/stan" ->
            if (parowanie.tokenOk(naglowki["authorization"])) 200 to Odczyt.stan(ctx)
            else 401 to JSONObject().put("blad", "brak albo zly token")
        else -> 404 to JSONObject().put("blad", "nie ma takiego endpointu")
    }

    private fun czytajLinie(wej: InputStream): String? {
        val sb = StringBuilder()
        while (sb.length < 8192) {
            val c = wej.read()
            if (c < 0) return if (sb.isEmpty()) null else sb.toString()
            if (c == '\n'.code) return sb.toString().trimEnd('\r')
            sb.append(c.toChar())
        }
        return sb.toString()
    }

    private fun opis(kod: Int) = when (kod) {
        200 -> "OK"; 401 -> "Unauthorized"; 403 -> "Forbidden"; else -> "Not Found"
    }

    companion object {
        const val PORT = 8765
        const val TAG = "KidwatchTV"
    }
}
