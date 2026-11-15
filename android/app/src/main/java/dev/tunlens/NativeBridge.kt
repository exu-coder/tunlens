package dev.tunlens

/**
 * The whole native surface of tunlens.
 *
 * Deliberately small: start/stop the capture path, hand over the tun fd, and
 * receive JSON events. Compare with the app this was reconstructed from, whose
 * bridge also exposed `setKey`, `editAndSend` and a signature gate — those are
 * the parts that made it a cheat, and they do not exist here.
 *
 * Symbols live in `libtunlens.so` as `Java_dev_tunlens_NativeBridge_*`.
 */
object NativeBridge {

    init {
        System.loadLibrary("tunlens")
    }

    interface Listener {
        /** Called on a native thread; marshall to the main thread yourself. */
        fun onEvent(json: String)
    }

    external fun version(): String

    external fun setListener(listener: Listener): Boolean

    external fun clearListener()

    /** Local SOCKS5 capture point; convenient when testing from a shell. */
    external fun startSocks(port: Int): Boolean

    external fun stopSocks()

    /** Takes ownership of a VpnService tun fd for the lifetime of the call. */
    external fun startTun(fd: Int): Boolean

    external fun stopTun()

    external fun isRunning(): Boolean

    external fun connectionCount(): Int
}
