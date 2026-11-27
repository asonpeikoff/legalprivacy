package org.legalprivacy.core

import java.util.Random
import kotlin.math.ln

/** How often the noise acts. [perHour] is an average; gaps are random (exponential), so the rhythm never looks metronomic. */
object Pacing {
    val LEVELS = mapOf("low" to 30.0, "medium" to 120.0, "high" to 400.0)

    fun gapSeconds(perHour: Double, rng: Random = Random()): Double {
        require(perHour > 0)
        val u = 1.0 - rng.nextDouble()
        return (-ln(u) * 3600.0 / perHour).coerceIn(0.5, 1800.0)
    }
}
