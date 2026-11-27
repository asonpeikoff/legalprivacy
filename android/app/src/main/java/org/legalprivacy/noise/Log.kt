package org.legalprivacy.noise

import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale

/** An in-memory log (never written to disk, gone when the app stops), newest last. */
object Log {
    private val lines = ArrayDeque<String>()
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    @Synchronized fun add(msg: String) {
        lines.addLast("${fmt.format(Date())}  $msg")
        while (lines.size > 300) lines.removeFirst()
    }

    @Synchronized fun text(max: Int = 120): String = lines.toList().takeLast(max).joinToString("\n")
    @Synchronized fun clear() = lines.clear()
}
