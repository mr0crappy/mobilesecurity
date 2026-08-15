package com.example.mobilesecurity.monitor

import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager

data class AppNetworkUsage(
    val packageName: String,
    val appName: String,
    val uid: Int,
    val rxBytes: Long,
    val txBytes: Long,
    val totalBytes: Long
)

class NetworkUsageMonitor(
    private val context: Context
) {

    private val networkStatsManager =
        context.getSystemService(
            Context.NETWORK_STATS_SERVICE
        ) as NetworkStatsManager

    private val packageManager =
        context.packageManager

    fun getAllAppNetworkUsage(): List<AppNetworkUsage> {

        val endTime =
            System.currentTimeMillis()

        val startTime =
            endTime -
                    (24L * 60L * 60L * 1000L)

        val apps =
            packageManager.getInstalledApplications(
                PackageManager.GET_META_DATA
            )

        val results =
            mutableListOf<AppNetworkUsage>()

        for (app in apps) {

            val usage =
                getUsageForUid(
                    app.uid,
                    startTime,
                    endTime
                )

            if (usage != null) {

                val appName =
                    packageManager
                        .getApplicationLabel(app)
                        .toString()

                results.add(
                    AppNetworkUsage(
                        packageName =
                            app.packageName,

                        appName =
                            appName,

                        uid =
                            app.uid,

                        rxBytes =
                            usage.first,

                        txBytes =
                            usage.second,

                        totalBytes =
                            usage.first +
                                    usage.second
                    )
                )
            }
        }

        return results
            .sortedByDescending {
                it.totalBytes
            }
    }

    private fun getUsageForUid(
        uid: Int,
        startTime: Long,
        endTime: Long
    ): Pair<Long, Long>? {

        return try {

            val stats =
                networkStatsManager
                    .queryDetailsForUid(
                        ConnectivityManager.TYPE_WIFI,
                        null,
                        startTime,
                        endTime,
                        uid
                    )

            var rxBytes = 0L
            var txBytes = 0L

            val bucket =
                NetworkStats.Bucket()

            while (
                stats.hasNextBucket()
            ) {

                stats.getNextBucket(bucket)

                rxBytes +=
                    bucket.rxBytes

                txBytes +=
                    bucket.txBytes
            }

            stats.close()

            Pair(
                rxBytes,
                txBytes
            )

        } catch (
            e: SecurityException
        ) {

            null

        } catch (
            e: Exception
        ) {

            null
        }
    }
}