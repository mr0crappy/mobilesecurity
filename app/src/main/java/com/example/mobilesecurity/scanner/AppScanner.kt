package com.example.mobilesecurity.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager

class AppScanner(private val context: Context) {

    private val packageManager = context.packageManager

    fun scanApps(): List<AppInfo> {

        val packages = packageManager.getInstalledApplications(
            PackageManager.ApplicationInfoFlags.of(0)
        )

        return packages
            .filter {
                it.flags and ApplicationInfo.FLAG_SYSTEM == 0
            }
            .mapNotNull { app ->
                scanApp(app)
            }
    }

    private fun scanApp(app: ApplicationInfo): AppInfo? {

        val packageInfo = packageManager.getPackageInfo(
            app.packageName,
            PackageManager.PackageInfoFlags.of(
                PackageManager.GET_PERMISSIONS.toLong()
            )
        )

        val permissions =
            packageInfo.requestedPermissions?.toList()
                ?: emptyList()

        val dangerousPermissions =
            permissions.count { isDangerousPermission(it) }

        val riskScore =
            calculateRisk(
                permissions,
                dangerousPermissions
            )

        return AppInfo(
            name = app.loadLabel(packageManager).toString(),
            packageName = app.packageName,
            versionName = packageInfo.versionName,
            permissions = permissions,
            permissionCount = permissions.size,
            dangerousPermissionCount = dangerousPermissions,
            riskScore = riskScore,
            riskLevel = getRiskLevel(riskScore)
        )
    }

    private fun isDangerousPermission(permission: String): Boolean {

        val dangerous = setOf(
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.READ_PHONE_STATE"
        )

        return permission in dangerous
    }

    private fun calculateRisk(
        permissions: List<String>,
        dangerousCount: Int
    ): Int {

        var score = 0

        score += dangerousCount * 7

        if (
            "android.permission.INTERNET" in permissions
        ) {
            score += 5
        }

        if (
            "android.permission.REQUEST_INSTALL_PACKAGES" in permissions
        ) {
            score += 20
        }

        if (
            "android.permission.SYSTEM_ALERT_WINDOW" in permissions
        ) {
            score += 15
        }

        return score.coerceIn(0, 100)
    }

    private fun getRiskLevel(score: Int): String {

        return when {
            score <= 30 -> "SAFE"
            score <= 60 -> "LOW RISK"
            score <= 80 -> "SUSPICIOUS"
            else -> "HIGH RISK"
        }
    }
}