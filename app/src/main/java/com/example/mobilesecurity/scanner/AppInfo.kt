package com.example.mobilesecurity.scanner

data class AppInfo(
    val name: String,
    val packageName: String,
    val versionName: String?,
    val permissions: List<String>,
    val permissionCount: Int,
    val dangerousPermissionCount: Int,
    val riskScore: Int,
    val riskLevel: String
)