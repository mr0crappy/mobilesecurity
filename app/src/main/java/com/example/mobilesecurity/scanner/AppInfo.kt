package com.example.mobilesecurity.scanner

data class AppInfo(

    val name: String,

    val packageName: String,

    val versionName: String?,

    val permissions: List<String>,

    val permissionCount: Int,

    val dangerousPermissionCount: Int,

    val riskScore: Int,

    val riskLevel: String,

    val aiMalicious: Boolean = false,

    val aiConfidence: Float = 0f,

    val aiBenignProbability: Float = 0f,

    val aiMaliciousProbability: Float = 0f,

    val activeAiFeatures: Int = 0
)