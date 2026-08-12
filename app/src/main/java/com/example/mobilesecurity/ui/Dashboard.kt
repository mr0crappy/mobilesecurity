package com.example.mobilesecurity.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

import com.example.mobilesecurity.monitor.BehaviorMonitor
import com.example.mobilesecurity.monitor.BehaviorResult
import com.example.mobilesecurity.scanner.AppInfo
import com.example.mobilesecurity.scanner.AppScanner

@Composable
fun Dashboard(
    scanner: AppScanner,
    behaviorMonitor: BehaviorMonitor
) {

    var apps by remember {
        mutableStateOf<List<AppInfo>>(emptyList())
    }

    var behaviorResults by remember {
        mutableStateOf<List<BehaviorResult>>(emptyList())
    }

    var scanning by remember {
        mutableStateOf(false)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {

        Text(
            text = "Mobile Security",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(
            modifier = Modifier.height(16.dp)
        )

        Button(
            onClick = {

                scanning = true

                apps = scanner.scanApps()

                behaviorResults =
                    behaviorMonitor.getUsageStats()

                scanning = false
            },

            modifier = Modifier.fillMaxWidth()
        ) {

            Text(
                if (scanning)
                    "Scanning..."
                else
                    "Scan Device"
            )
        }

        Spacer(
            modifier = Modifier.height(20.dp)
        )

        if (apps.isNotEmpty()) {

            ScanSummary(apps)

            Spacer(
                modifier = Modifier.height(20.dp)
            )

            Text(
                text = "Behavior Monitoring",
                style = MaterialTheme.typography.titleLarge
            )

            Spacer(
                modifier = Modifier.height(8.dp)
            )

            LazyColumn(
                verticalArrangement =
                    Arrangement.spacedBy(8.dp)
            ) {

                items(
                    behaviorResults
                ) { behavior ->

                    BehaviorCard(
                        behavior
                    )
                }
            }
        }
    }
}

@Composable
fun BehaviorCard(
    behavior: BehaviorResult
) {

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {

        Column(
            modifier = Modifier.padding(16.dp)
        ) {

            Text(
                text = behavior.packageName,
                style = MaterialTheme.typography.titleMedium
            )

            Spacer(
                modifier = Modifier.height(6.dp)
            )

            Text(
                text =
                    "Foreground: " +
                            String.format(
                                "%.1f",
                                behavior.foregroundMinutes
                            ) +
                            " minutes"
            )

            Text(
                text =
                    "Launches: " +
                            behavior.launchCount
            )

            Text(
                text =
                    "Launches/hour: " +
                            String.format(
                                "%.2f",
                                behavior.launchesPerHour
                            )
            )
            Text(
                text = "Activity events: ${behavior.activityEvents}"
            )

            Spacer(
                modifier = Modifier.height(6.dp)
            )

            Text(
                text =
                    "Behavior Score: " +
                            "${behavior.behaviorScore}/100"
            )

        }
    }
}
@Composable
fun ScanSummary(apps: List<AppInfo>) {

    val safe = apps.count {
        it.riskLevel == "SAFE"
    }

    val lowRisk = apps.count {
        it.riskLevel == "LOW RISK"
    }

    val suspicious = apps.count {
        it.riskLevel == "SUSPICIOUS"
    }

    val highRisk = apps.count {
        it.riskLevel == "HIGH RISK"
    }

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {

        Column(
            modifier = Modifier.padding(16.dp)
        ) {

            Text(
                text = "Scan Results",
                style = MaterialTheme.typography.titleMedium
            )

            Spacer(
                modifier = Modifier.height(8.dp)
            )

            Text(
                text = "Applications scanned: ${apps.size}"
            )

            Spacer(
                modifier = Modifier.height(8.dp)
            )

            Text("🟢 Safe: $safe")
            Text("🟡 Low Risk: $lowRisk")
            Text("🟠 Suspicious: $suspicious")
            Text("🔴 High Risk: $highRisk")
        }
    }
}