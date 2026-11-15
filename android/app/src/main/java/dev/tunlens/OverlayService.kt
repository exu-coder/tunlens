package dev.tunlens

import android.app.Service
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.IBinder
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Floating list of recent events, the same idea as the original app's overlay
 * but strictly read-only: it renders text and nothing else. There is no tap to
 * edit and no tap to re-inject.
 */
class OverlayService : Service() {

    private lateinit var windowManager: WindowManager
    private var panel: LinearLayout? = null
    private lateinit var lines: TextView

    private val recent = ArrayDeque<String>()
    private val clock = SimpleDateFormat("HH:mm:ss", Locale.US)
    private val onEvent: (CaptureEvent) -> Unit = { event ->
        val line = "${clock.format(Date(event.tsMs))}  ${event.line()}"
        recent.addLast(line)
        while (recent.size > MAX_LINES) recent.removeFirst()
        lines.text = recent.joinToString("\n")
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        windowManager = getSystemService(WINDOW_SERVICE) as WindowManager
        show()
        CaptureBus.register(onEvent)
    }

    override fun onDestroy() {
        CaptureBus.unregister(onEvent)
        panel?.let { runCatching { windowManager.removeView(it) } }
        panel = null
        super.onDestroy()
    }

    private fun show() {
        val density = resources.displayMetrics.density
        fun dp(value: Int) = (value * density).toInt()

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.argb(226, 16, 20, 24))
            setPadding(dp(10), dp(8), dp(10), dp(8))
        }

        val header = TextView(this).apply {
            text = "tunlens"
            setTextColor(Color.parseColor("#7fd1ff"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        }

        lines = TextView(this).apply {
            setTextColor(Color.parseColor("#e6edf3"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            text = "waiting for traffic…"
        }

        val close = TextView(this).apply {
            text = "×"
            setTextColor(Color.parseColor("#ff8f8f"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            setPadding(dp(12), 0, dp(4), 0)
            setOnClickListener { stopSelf() }
        }

        root.addView(LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(header, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(close)
        })
        root.addView(lines, LinearLayout.LayoutParams(dp(260), LinearLayout.LayoutParams.WRAP_CONTENT))

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
            PixelFormat.TRANSLUCENT,
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            x = dp(12)
            y = dp(120)
        }

        // Drag to move; the panel never takes input focus otherwise.
        root.setOnTouchListener(object : View.OnTouchListener {
            private var startX = 0
            private var startY = 0
            private var touchX = 0f
            private var touchY = 0f

            override fun onTouch(view: View, event: MotionEvent): Boolean {
                when (event.action) {
                    MotionEvent.ACTION_DOWN -> {
                        startX = params.x
                        startY = params.y
                        touchX = event.rawX
                        touchY = event.rawY
                        return true
                    }
                    MotionEvent.ACTION_MOVE -> {
                        params.x = startX + (event.rawX - touchX).toInt()
                        params.y = startY + (event.rawY - touchY).toInt()
                        runCatching { windowManager.updateViewLayout(root, params) }
                        return true
                    }
                }
                return false
            }
        })

        runCatching { windowManager.addView(root, params) }
            .onFailure { stopSelf() }
        panel = root
    }

    companion object {
        private const val MAX_LINES = 12
    }
}
