package com.example.mobilesecurity.monitor

data class BehaviorResult(
    val packageName: String,

    // Usage
    val totalTimeForeground: Long,
    val foregroundMinutes: Double,

    // Activity
    val launchCount: Int,
    val launchesPerHour: Double,

    // Timing
    val lastTimeUsed: Long,

    // Behavioral analysis
    val activityEvents: Int,
    val behaviorScore: Int
)