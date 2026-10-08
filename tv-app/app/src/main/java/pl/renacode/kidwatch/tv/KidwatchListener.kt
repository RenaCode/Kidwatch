package pl.renacode.kidwatch.tv

import android.content.ComponentName
import android.service.notification.NotificationListenerService
import android.util.Log

/**
 * Wlaczony "nasluchiwacz powiadomien" - jedyna droga do sesji odtwarzaczy
 * innych aplikacji (MediaSessionManager.getActiveSessions). System wiaze
 * go sam po starcie telewizora, wiec tu zyje serwer HTTP.
 *
 * Tresci powiadomien nie czytamy: onNotificationPosted nie jest nadpisane.
 */
class KidwatchListener : NotificationListenerService() {
    private var serwer: Serwer? = null

    override fun onListenerConnected() {
        Log.i(Serwer.TAG, "nasluchiwacz polaczony")
        serwer = Serwer(applicationContext).also { it.start() }
    }

    override fun onListenerDisconnected() {
        Log.w(Serwer.TAG, "nasluchiwacz rozlaczony - prosze o ponowne wiazanie")
        serwer?.stop()
        serwer = null
        requestRebind(ComponentName(this, KidwatchListener::class.java))
    }

    override fun onDestroy() {
        serwer?.stop()
        super.onDestroy()
    }
}
