package com.example.mobilesecurity.monitor

import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context

class BehaviorMonitor(
    private val context: Context
) {

    private val usageStatsManager =
        context.getSystemService(
            Context.USAGE_STATS_SERVICE
        ) as UsageStatsManager

    fun getUsageStats(): List<BehaviorResult> {

        val endTime = System.currentTimeMillis()

        val startTime =
            endTime - (24 * 60 * 60 * 1000L)

        val usageStats =
            usageStatsManager.queryUsageStats(
                UsageStatsManager.INTERVAL_DAILY,
                startTime,
                endTime
            )

        val launchCounts =
            mutableMapOf<String, Int>()

        val activityEvents =
            mutableMapOf<String, Int>()

        val events =
            usageStatsManager.queryEvents(
                startTime,
                endTime
            )

        val event = UsageEvents.Event()

        while (events.hasNextEvent()) {

            events.getNextEvent(event)

            val packageName =
                event.packageName

            if (
                event.eventType ==
                UsageEvents.Event.ACTIVITY_RESUMED
            ) {

                launchCounts[packageName] =
                    (launchCounts[packageName] ?: 0) + 1

                activityEvents[packageName] =
                    (activityEvents[packageName] ?: 0) + 1
            }
        }

        return usageStats
            .filter {
                it.totalTimeInForeground > 0
            }
            .map {

                val packageName =
                    it.packageName

                val launches =
                    launchCounts[packageName] ?: 0

                val eventsCount =
                    activityEvents[packageName] ?: 0

                val foregroundMinutes =
                    it.totalTimeInForeground /
                            60000.0

                val launchesPerHour =
                    launches / 24.0

                val behaviorScore =
                    calculateBehaviorScore(
                        launchesPerHour,
                        foregroundMinutes,
                        eventsCount
                    )

                BehaviorResult(

                    packageName =
                        packageName,

                    totalTimeForeground =
                        it.totalTimeInForeground,

                    foregroundMinutes =
                        foregroundMinutes,

                    launchCount =
                        launches,

                    launchesPerHour =
                        launchesPerHour,

                    lastTimeUsed =
                        it.lastTimeUsed,

                    activityEvents =
                        eventsCount,

                    behaviorScore =
                        behaviorScore
                )
            }
            .sortedByDescending {
                it.behaviorScore
            }
    }

    private fun calculateBehaviorScore(
        launchesPerHour: Double,
        foregroundMinutes: Double,
        activityEvents: Int
    ): Int {

        var score = 0

        // Frequent activity
        if (launchesPerHour > 10) {
            score += 30
        } else if (launchesPerHour > 5) {
            score += 15
        }

        // Very high foreground usage
        if (foregroundMinutes > 300) {
            score += 20
        } else if (foregroundMinutes > 120) {
            score += 10
        }

        // Large number of activity events
        if (activityEvents > 100) {
            score += 30
        } else if (activityEvents > 50) {
            score += 15
        }

        return score.coerceIn(0, 100)
    }
}