package com.example.mobilesecurity.monitor

data class AppSecurityResult(
    val packageName: String,
    val appName: String,

    val staticRisk: String,

    val behaviorScore: Int,

    val networkBytes: Long,

    val overallScore: Int,

    val riskLevel: String
)