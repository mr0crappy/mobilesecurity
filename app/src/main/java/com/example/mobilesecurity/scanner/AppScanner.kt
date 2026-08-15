package com.example.mobilesecurity.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.util.Log

class AppScanner(
    private val context: Context
) {

    private val packageManager =
        context.packageManager


    // ==================================================
    // SCAN INSTALLED APPS
    // ==================================================

    fun scanApps(): List<AppInfo> {

        @Suppress("DEPRECATION")
        val packages =
            packageManager.getInstalledApplications(0)

        return packages

            // Only user-installed apps
            .filter { app ->

                (app.flags and
                        ApplicationInfo.FLAG_SYSTEM) == 0
            }

            // CHEAP scan only
            .mapNotNull { app ->

                scanApp(app)
            }

            .sortedByDescending { app ->

                app.riskScore
            }
    }


    // ==================================================
    // STATIC / PERMISSION SCAN ONLY
    // ==================================================

    private fun scanApp(
        app: ApplicationInfo
    ): AppInfo? {

        return try {

            Log.d(
                "APP_SCAN",
                "Scanning ${app.packageName}"
            )


            // ------------------------------------------
            // PACKAGE INFORMATION
            // ------------------------------------------

            @Suppress("DEPRECATION")
            val packageInfo =
                packageManager.getPackageInfo(
                    app.packageName,
                    PackageManager.GET_PERMISSIONS
                )


            // ------------------------------------------
            // PERMISSIONS
            // ------------------------------------------

            val permissions =
                packageInfo.requestedPermissions
                    ?.toList()
                    ?: emptyList()


            val dangerousPermissionCount =
                permissions.count { permission ->

                    isDangerousPermission(
                        permission
                    )
                }


            // ------------------------------------------
            // BASIC RISK
            // ------------------------------------------

            val riskScore =
                calculateRisk(
                    permissions,
                    dangerousPermissionCount
                )


            // ------------------------------------------
            // APP INFO
            // ------------------------------------------

            AppInfo(

                name =
                    app.loadLabel(
                        packageManager
                    ).toString(),

                packageName =
                    app.packageName,

                versionName =
                    packageInfo.versionName,

                permissions =
                    permissions,

                permissionCount =
                    permissions.size,

                dangerousPermissionCount =
                    dangerousPermissionCount,

                riskScore =
                    riskScore,

                riskLevel =
                    getRiskLevel(
                        riskScore
                    ),

                // AI is NOT run here.
                //
                // These values should have defaults
                // in AppInfo.
                aiMalicious =
                    false,

                aiConfidence =
                    0f,

                aiBenignProbability =
                    0f,

                aiMaliciousProbability =
                    0f
            )

        } catch (e: Exception) {

            Log.e(
                "APP_SCAN",
                "FAILED ${app.packageName}: ${e.message}",
                e
            )

            null
        }
    }


    // ==================================================
    // SCAN ONE APP
    // ==================================================

    fun scanSingleApp(
        packageName: String
    ): AppInfo? {

        return try {

            val applicationInfo =
                packageManager.getApplicationInfo(
                    packageName,
                    0
                )


            // Don't analyze system apps
            if (
                applicationInfo.flags and
                ApplicationInfo.FLAG_SYSTEM != 0
            ) {

                return null
            }


            // IMPORTANT:
            //
            // This only gets the cheap app information.
            //
            // V6 AI analysis is now handled by
            // AppDetailsActivity.

            scanApp(
                applicationInfo
            )

        } catch (e: Exception) {

            Log.e(
                "APP_SCAN",
                "Single app scan failed: $packageName",
                e
            )

            null
        }
    }


    // ==================================================
    // DANGEROUS PERMISSIONS
    // ==================================================

    private fun isDangerousPermission(
        permission: String
    ): Boolean {

        val dangerousPermissions =
            setOf(

                "android.permission.READ_SMS",

                "android.permission.SEND_SMS",

                "android.permission.RECEIVE_SMS",

                "android.permission.READ_CONTACTS",

                "android.permission.WRITE_CONTACTS",

                "android.permission.RECORD_AUDIO",

                "android.permission.CAMERA",

                "android.permission.ACCESS_FINE_LOCATION",

                "android.permission.ACCESS_COARSE_LOCATION",

                "android.permission.READ_CALL_LOG",

                "android.permission.WRITE_CALL_LOG",

                "android.permission.READ_PHONE_STATE",

                "android.permission.READ_EXTERNAL_STORAGE",

                "android.permission.WRITE_EXTERNAL_STORAGE"
            )

        return permission in dangerousPermissions
    }


    // ==================================================
    // RISK CALCULATION
    // ==================================================

    private fun calculateRisk(
        permissions: List<String>,
        dangerousCount: Int
    ): Int {

        var score = 0


        // Dangerous permissions
        score +=
            dangerousCount * 7


        // Internet
        if (
            "android.permission.INTERNET"
            in permissions
        ) {

            score += 5
        }


        // Install APKs
        if (
            "android.permission.REQUEST_INSTALL_PACKAGES"
            in permissions
        ) {

            score += 20
        }


        // Draw over other apps
        if (
            "android.permission.SYSTEM_ALERT_WINDOW"
            in permissions
        ) {

            score += 15
        }


        // Accessibility
        if (
            "android.permission.BIND_ACCESSIBILITY_SERVICE"
            in permissions
        ) {

            score += 20
        }


        // Start after boot
        if (
            "android.permission.RECEIVE_BOOT_COMPLETED"
            in permissions
        ) {

            score += 10
        }


        // Query installed packages
        if (
            "android.permission.QUERY_ALL_PACKAGES"
            in permissions
        ) {

            score += 10
        }


        // Usage statistics
        if (
            "android.permission.PACKAGE_USAGE_STATS"
            in permissions
        ) {

            score += 5
        }


        return score.coerceIn(
            0,
            100
        )
    }


    // ==================================================
    // RISK LEVEL
    // ==================================================

    private fun getRiskLevel(
        score: Int
    ): String {

        return when {

            score <= 30 ->
                "SAFE"

            score <= 60 ->
                "LOW RISK"

            score <= 80 ->
                "SUSPICIOUS"

            else ->
                "HIGH RISK"
        }
    }
}