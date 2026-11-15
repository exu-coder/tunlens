package dev.tunlens

import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import java.util.concurrent.CopyOnWriteArrayList

/**
 * One observed event, exactly as the Rust engine emits it. The schema is the
 * engine's: see `src/events.rs` for the single source of truth.
 */
data class CaptureEvent(
    val tsMs: Long,
    val host: String,
    val port: Int,
    val direction: String,
    val protocol: String,
    val op: String,
    val summary: String,
    val bytes: Int,
    val rawHex: String,
    val flow: String,
) {
    /** Compact one-liner for the overlay and the log view. */
    fun line(): String {
        val arrow = if (direction == "client") "->" else "<-"
        return "$arrow ${host}:$port  $summary"
    }

    companion object {
        fun parse(json: String): CaptureEvent? = runCatching {
            val o = JSONObject(json)
            CaptureEvent(
                tsMs = o.optLong("ts_ms"),
                host = o.optString("host"),
                port = o.optInt("port"),
                direction = o.optString("direction"),
                protocol = o.optString("protocol"),
                op = o.optString("op"),
                summary = o.optString("summary"),
                bytes = o.optInt("bytes"),
                rawHex = o.optString("raw_hex"),
                flow = o.optString("flow"),
            )
        }.getOrNull()
    }
}

/**
 * In-process fan-out from the native listener to whatever is on screen. Events
 * always arrive on the main thread, so views can be touched directly.
 */
object CaptureBus {

    private val handlers = CopyOnWriteArrayList<(CaptureEvent) -> Unit>()
    private val main = Handler(Looper.getMainLooper())
    private val listener = object : NativeBridge.Listener {
        override fun onEvent(json: String) {
            val event = CaptureEvent.parse(json) ?: return
            main.post { handlers.forEach { it(event) } }
        }
    }

    fun register(handler: (CaptureEvent) -> Unit) {
        handlers.addIfAbsent(handler)
        NativeBridge.setListener(listener)
    }

    fun unregister(handler: (CaptureEvent) -> Unit) {
        handlers.remove(handler)
        if (handlers.isEmpty()) {
            NativeBridge.clearListener()
        }
    }
}
