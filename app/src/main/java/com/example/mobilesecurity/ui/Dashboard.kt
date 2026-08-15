package com.example.mobilesecurity.ui

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.platform.LocalContext

import com.example.mobilesecurity.AppListActivity
import com.example.mobilesecurity.monitor.AppNetworkUsage
import com.example.mobilesecurity.monitor.AppSecurityResult
import com.example.mobilesecurity.monitor.BehaviorMonitor
import com.example.mobilesecurity.monitor.BehaviorResult
import com.example.mobilesecurity.monitor.NetworkUsageMonitor
import com.example.mobilesecurity.monitor.NetworkVpnService
import com.example.mobilesecurity.monitor.SecurityRiskEngine
import com.example.mobilesecurity.scanner.AppInfo
import com.example.mobilesecurity.scanner.AppScanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext


@Composable
fun Dashboard(
    scanner: AppScanner,
    behaviorMonitor: BehaviorMonitor,
    networkUsageMonitor: NetworkUsageMonitor,
    onStartVpn: () -> Unit,
    onStopVpn: () -> Unit
) {

    // ======================================================
    // STATE
    // ======================================================

    var apps by remember {
        mutableStateOf<List<AppInfo>>(emptyList())
    }

    var behaviorResults by remember {
        mutableStateOf<List<BehaviorResult>>(emptyList())
    }

    var networkUsage by remember {
        mutableStateOf<List<AppNetworkUsage>>(emptyList())
    }

    var securityResults by remember {
        mutableStateOf<List<AppSecurityResult>>(emptyList())
    }

    var scanning by remember {
        mutableStateOf(false)
    }

    var showNetwork by remember {
        mutableStateOf(false)
    }

    var showSecurity by remember {
        mutableStateOf(false)
    }

    // ======================================================
    // CONTEXT / COROUTINE
    // ======================================================

    val context = LocalContext.current

    val scope =
        rememberCoroutineScope()

    val networkState by
    NetworkVpnService.state.collectAsState()

    val riskEngine =
        remember {
            SecurityRiskEngine()
        }


    // ======================================================
    // RISK COUNTS
    // ======================================================

    val highRisk =
        securityResults.count {
            it.riskLevel == "HIGH"
        }

    val suspicious =
        securityResults.count {
            it.riskLevel == "SUSPICIOUS"
        }

    val lowRisk =
        securityResults.count {
            it.riskLevel == "LOW"
        }

    val safe =
        securityResults.count {
            it.riskLevel == "SAFE"
        }


    // ======================================================
    // AVERAGE RISK
    // ======================================================

    val averageRisk =
        if (securityResults.isEmpty()) {

            0

        } else {

            securityResults
                .map {
                    it.overallScore
                }
                .average()
                .toInt()
        }


    // ======================================================
    // DEVICE STATUS
    // ======================================================

    val status =
        when {

            highRisk > 0 ->
                "HIGH RISK"

            suspicious > 0 ->
                "SUSPICIOUS"

            lowRisk > 0 ->
                "LOW RISK"

            securityResults.isNotEmpty() ->
                "DEVICE SECURE"

            else ->
                "NOT SCANNED"
        }


    // ======================================================
    // DASHBOARD
    // ======================================================

    Column(

        modifier =
            Modifier
                .fillMaxSize()
                .windowInsetsPadding(
                    WindowInsets.statusBars
                )
                .verticalScroll(
                    rememberScrollState()
                )
                .padding(16.dp),

        verticalArrangement =
            Arrangement.spacedBy(12.dp)
    ) {

        // ==================================================
        // HEADER
        // ==================================================

        Column {

            Text(
                text = "🛡 Mobile Security",

                style =
                    MaterialTheme
                        .typography
                        .headlineMedium,

                fontWeight =
                    FontWeight.Bold
            )

            Text(
                text =
                    "Device protection dashboard",

                style =
                    MaterialTheme
                        .typography
                        .bodyMedium
            )
        }


        // ==================================================
        // SECURITY STATUS
        // ==================================================

        SecurityStatusCard(

            status =
                status,

            score =
                averageRisk,

            apps =
                apps.size,

            threats =
                highRisk + suspicious
        )


        // ==================================================
        // SCAN DEVICE
        // ==================================================

        Button(

            onClick = {

                if (scanning) {
                    return@Button
                }

                scanning = true

                scope.launch {

                    try {

                        // ==================================
                        // 1. STATIC + AI SCAN
                        // ==================================

                        val scannedApps =
                            withContext(
                                Dispatchers.IO
                            ) {

                                scanner.scanApps()
                            }

                        apps =
                            scannedApps


                        // ==================================
                        // 2. BEHAVIOR SCAN
                        // ==================================

                        val scannedBehavior =
                            withContext(
                                Dispatchers.IO
                            ) {

                                behaviorMonitor
                                    .getUsageStats()
                            }

                        behaviorResults =
                            scannedBehavior


                        // ==================================
                        // 3. CREATE LOOKUP MAPS
                        // ==================================

                        val behaviorMap =
                            scannedBehavior
                                .associateBy {
                                    it.packageName
                                }

                        val networkMap =
                            networkUsage
                                .associateBy {
                                    it.packageName
                                }


                        // ==================================
                        // 4. SECURITY ANALYSIS
                        // ==================================

                        val results =
                            scannedApps.map { app ->

                                val behavior =
                                    behaviorMap[
                                        app.packageName
                                    ]

                                val network =
                                    networkMap[
                                        app.packageName
                                    ]

                                riskEngine.calculateRisk(

                                    appName =
                                        app.name,

                                    packageName =
                                        app.packageName,

                                    staticRisk =
                                        app.riskLevel,

                                    behaviorScore =
                                        behavior
                                            ?.behaviorScore
                                            ?: 0,

                                    networkBytes =
                                        network
                                            ?.totalBytes
                                            ?: 0L
                                )
                            }

                        securityResults =
                            results

                    } catch (e: Exception) {

                        e.printStackTrace()

                    } finally {

                        scanning = false
                    }
                }
            },

            enabled =
                !scanning,

            modifier =
                Modifier.fillMaxWidth(),

            shape =
                RoundedCornerShape(14.dp)

        ) {

            Text(

                text =
                    if (scanning)
                        "Scanning..."
                    else
                        "🔍  Scan Device"
            )
        }


        // ==================================================
        // THREAT SUMMARY
        // ==================================================

        if (securityResults.isNotEmpty()) {

            ThreatSummary(

                safe =
                    safe,

                low =
                    lowRisk,

                suspicious =
                    suspicious,

                high =
                    highRisk
            )
        }


        // ==================================================
        // NETWORK MONITOR
        // ==================================================

        NetworkSummaryCard(

            isRunning =
                networkState.isRunning,

            packets =
                networkState.totalPackets,

            data =
                formatBytes(
                    networkState.totalBytes
                ),

            onStart =
                onStartVpn,

            onStop =
                onStopVpn
        )


        // ==================================================
        // NETWORK USAGE SCAN
        // ==================================================

        OutlinedButton(

            onClick = {

                scope.launch {

                    try {

                        val usage =
                            withContext(
                                Dispatchers.IO
                            ) {

                                networkUsageMonitor
                                    .getAllAppNetworkUsage()
                            }

                        networkUsage =
                            usage


                        val networkMap =
                            usage.associateBy {
                                it.packageName
                            }

                        val behaviorMap =
                            behaviorResults
                                .associateBy {
                                    it.packageName
                                }


                        val results =
                            apps.map { app ->

                                val behavior =
                                    behaviorMap[
                                        app.packageName
                                    ]

                                val network =
                                    networkMap[
                                        app.packageName
                                    ]

                                riskEngine.calculateRisk(

                                    appName =
                                        app.name,

                                    packageName =
                                        app.packageName,

                                    staticRisk =
                                        app.riskLevel,

                                    behaviorScore =
                                        behavior
                                            ?.behaviorScore
                                            ?: 0,

                                    networkBytes =
                                        network
                                            ?.totalBytes
                                            ?: 0L
                                )
                            }

                        securityResults =
                            results

                    } catch (e: Exception) {

                        e.printStackTrace()
                    }
                }
            },

            modifier =
                Modifier.fillMaxWidth(),

            shape =
                RoundedCornerShape(14.dp)

        ) {

            Text(
                "📊  Scan Network Usage"
            )
        }


        // ==================================================
        // INSTALLED APPS
        // ==================================================

        if (apps.isNotEmpty()) {

            OutlinedButton(

                onClick = {

                    context.startActivity(
                        Intent(
                            context,
                            AppListActivity::class.java
                        )
                    )
                },

                modifier =
                    Modifier.fillMaxWidth(),

                shape =
                    RoundedCornerShape(14.dp)

            ) {

                Text(
                    "📱  View Installed Apps"
                )
            }
        }


        // ==================================================
        // SECURITY ANALYSIS
        // ==================================================

        if (securityResults.isNotEmpty()) {

            OutlinedButton(

                onClick = {

                    showSecurity =
                        true
                },

                modifier =
                    Modifier.fillMaxWidth(),

                shape =
                    RoundedCornerShape(14.dp)

            ) {

                Text(
                    "🛡  View Security Analysis"
                )
            }
        }


        // ==================================================
        // NETWORK USAGE
        // ==================================================

        if (networkUsage.isNotEmpty()) {

            OutlinedButton(

                onClick = {

                    showNetwork =
                        true
                },

                modifier =
                    Modifier.fillMaxWidth(),

                shape =
                    RoundedCornerShape(14.dp)

            ) {

                Text(
                    "🌐  View Network Usage"
                )
            }
        }


        // ==================================================
        // RECENT ALERTS
        // ==================================================

        if (securityResults.isNotEmpty()) {

            RecentAlerts(
                results =
                    securityResults
            )
        }
    }


    // ======================================================
    // SECURITY ANALYSIS DIALOG
    // ======================================================

    if (showSecurity) {

        AlertDialog(

            onDismissRequest = {

                showSecurity =
                    false
            },

            title = {

                Text(
                    "Security Analysis"
                )
            },

            text = {

                Column(

                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .verticalScroll(
                                rememberScrollState()
                            )
                ) {

                    securityResults.forEach { result ->

                        SecurityResultCard(
                            result =
                                result
                        )

                        Spacer(
                            modifier =
                                Modifier.height(8.dp)
                        )
                    }
                }
            },

            confirmButton = {

                TextButton(

                    onClick = {

                        showSecurity =
                            false
                    }

                ) {

                    Text("Close")
                }
            }
        )
    }


    // ======================================================
    // NETWORK USAGE DIALOG
    // ======================================================

    if (showNetwork) {

        AlertDialog(

            onDismissRequest = {

                showNetwork =
                    false
            },

            title = {

                Text(
                    "Network Usage"
                )
            },

            text = {

                Column(

                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .verticalScroll(
                                rememberScrollState()
                            )
                ) {

                    networkUsage.forEach { usage ->

                        NetworkUsageCard(
                            usage =
                                usage
                        )

                        Spacer(
                            modifier =
                                Modifier.height(8.dp)
                        )
                    }
                }
            },

            confirmButton = {

                TextButton(

                    onClick = {

                        showNetwork =
                            false
                    }

                ) {

                    Text("Close")
                }
            }
        )
    }
}


// ==========================================================
// SECURITY STATUS CARD
// ==========================================================

@Composable
fun SecurityStatusCard(
    status: String,
    score: Int,
    apps: Int,
    threats: Int
) {

    Card(

        modifier =
            Modifier.fillMaxWidth(),

        shape =
            RoundedCornerShape(20.dp)
    ) {

        Column(

            modifier =
                Modifier.padding(20.dp),

            horizontalAlignment =
                Alignment.CenterHorizontally
        ) {

            Text(
                text =
                    "DEVICE STATUS",

                style =
                    MaterialTheme
                        .typography
                        .labelLarge
            )

            Spacer(
                modifier =
                    Modifier.height(8.dp)
            )

            Text(

                text =
                    when (status) {

                        "HIGH RISK" ->
                            "🔴"

                        "SUSPICIOUS" ->
                            "🟠"

                        "LOW RISK" ->
                            "🟡"

                        "DEVICE SECURE" ->
                            "🟢"

                        else ->
                            "⚪"
                    },

                style =
                    MaterialTheme
                        .typography
                        .displaySmall
            )

            Text(

                text =
                    status,

                style =
                    MaterialTheme
                        .typography
                        .headlineSmall,

                fontWeight =
                    FontWeight.Bold
            )

            Spacer(
                modifier =
                    Modifier.height(16.dp)
            )

            Row(

                modifier =
                    Modifier.fillMaxWidth(),

                horizontalArrangement =
                    Arrangement.SpaceEvenly
            ) {

                MiniStat(
                    value =
                        "$score/100",

                    label =
                        "Risk"
                )

                MiniStat(
                    value =
                        apps.toString(),

                    label =
                        "Apps"
                )

                MiniStat(
                    value =
                        threats.toString(),

                    label =
                        "Threats"
                )
            }
        }
    }
}


// ==========================================================
// MINI STAT
// ==========================================================

@Composable
fun MiniStat(
    value: String,
    label: String
) {

    Column(

        horizontalAlignment =
            Alignment.CenterHorizontally
    ) {

        Text(

            text =
                value,

            fontWeight =
                FontWeight.Bold
        )

        Text(

            text =
                label,

            style =
                MaterialTheme
                    .typography
                    .bodySmall
        )
    }
}


// ==========================================================
// THREAT SUMMARY
// ==========================================================

@Composable
fun ThreatSummary(
    safe: Int,
    low: Int,
    suspicious: Int,
    high: Int
) {

    Card(

        modifier =
            Modifier.fillMaxWidth(),

        shape =
            RoundedCornerShape(18.dp)
    ) {

        Column(

            modifier =
                Modifier.padding(16.dp)
        ) {

            Text(

                text =
                    "Threat Overview",

                style =
                    MaterialTheme
                        .typography
                        .titleMedium,

                fontWeight =
                    FontWeight.Bold
            )

            Spacer(
                modifier =
                    Modifier.height(10.dp)
            )

            ThreatLine(
                icon = "🟢",
                label = "Safe",
                count = safe
            )

            ThreatLine(
                icon = "🟡",
                label = "Low Risk",
                count = low
            )

            ThreatLine(
                icon = "🟠",
                label = "Suspicious",
                count = suspicious
            )

            ThreatLine(
                icon = "🔴",
                label = "High",
                count = high
            )
        }
    }
}


@Composable
fun ThreatLine(
    icon: String,
    label: String,
    count: Int
) {

    Row(

        modifier =
            Modifier
                .fillMaxWidth()
                .padding(
                    vertical = 3.dp
                ),

        horizontalArrangement =
            Arrangement.SpaceBetween
    ) {

        Text(
            "$icon  $label"
        )

        Text(

            count.toString(),

            fontWeight =
                FontWeight.Bold
        )
    }
}


// ==========================================================
// NETWORK SUMMARY
// ==========================================================

@Composable
fun NetworkSummaryCard(
    isRunning: Boolean,
    packets: Int,
    data: String,
    onStart: () -> Unit,
    onStop: () -> Unit
) {

    Card(

        modifier =
            Modifier.fillMaxWidth(),

        shape =
            RoundedCornerShape(18.dp)
    ) {

        Column(

            modifier =
                Modifier.padding(16.dp)
        ) {

            Row(

                modifier =
                    Modifier.fillMaxWidth(),

                horizontalArrangement =
                    Arrangement.SpaceBetween
            ) {

                Column {

                    Text(

                        text =
                            "Network",

                        style =
                            MaterialTheme
                                .typography
                                .titleMedium,

                        fontWeight =
                            FontWeight.Bold
                    )

                    Text(

                        text =
                            if (isRunning)
                                "🟢 Monitoring active"
                            else
                                "⚪ Monitoring stopped"
                    )
                }

                Column(

                    horizontalAlignment =
                        Alignment.End
                ) {

                    Text(

                        text =
                            "$packets packets",

                        fontWeight =
                            FontWeight.Bold
                    )

                    Text(

                        text =
                            data,

                        style =
                            MaterialTheme
                                .typography
                                .bodySmall
                    )
                }
            }

            Spacer(
                modifier =
                    Modifier.height(10.dp)
            )

            if (isRunning) {

                OutlinedButton(

                    onClick =
                        onStop,

                    modifier =
                        Modifier.fillMaxWidth()

                ) {

                    Text(
                        "Stop Monitoring"
                    )
                }

            } else {

                Button(

                    onClick =
                        onStart,

                    modifier =
                        Modifier.fillMaxWidth()

                ) {

                    Text(
                        "Start Monitoring"
                    )
                }
            }
        }
    }
}


// ==========================================================
// RECENT ALERTS
// ==========================================================

@Composable
fun RecentAlerts(
    results: List<AppSecurityResult>
) {

    val alerts =
        results
            .filter {

                it.riskLevel == "HIGH" ||
                        it.riskLevel == "SUSPICIOUS"
            }
            .take(3)


    if (alerts.isEmpty()) {

        Card(

            modifier =
                Modifier.fillMaxWidth(),

            shape =
                RoundedCornerShape(18.dp)

        ) {

            Text(

                text =
                    "🟢 No suspicious applications detected",

                modifier =
                    Modifier.padding(16.dp)
            )
        }

        return
    }


    Card(

        modifier =
            Modifier.fillMaxWidth(),

        shape =
            RoundedCornerShape(18.dp)
    ) {

        Column(

            modifier =
                Modifier.padding(16.dp)
        ) {

            Text(

                text =
                    "Recent Alerts",

                style =
                    MaterialTheme
                        .typography
                        .titleMedium,

                fontWeight =
                    FontWeight.Bold
            )

            Spacer(
                modifier =
                    Modifier.height(8.dp)
            )


            alerts.forEach { result ->

                Text(

                    text =
                        getRiskIcon(
                            result.riskLevel
                        ) +
                                " " +
                                result.appName
                )

                Text(

                    text =
                        "   Risk score: " +
                                "${result.overallScore}/100",

                    style =
                        MaterialTheme
                            .typography
                            .bodySmall
                )

                Spacer(
                    modifier =
                        Modifier.height(6.dp)
                )
            }
        }
    }
}


// ==========================================================
// SECURITY RESULT CARD
// ==========================================================

@Composable
fun SecurityResultCard(
    result: AppSecurityResult
) {

    Card(

        modifier =
            Modifier.fillMaxWidth()
    ) {

        Column(

            modifier =
                Modifier.padding(12.dp)
        ) {

            Text(

                text =
                    getRiskIcon(
                        result.riskLevel
                    ) +
                            " " +
                            result.appName,

                fontWeight =
                    FontWeight.Bold
            )

            Text(

                text =
                    result.packageName,

                style =
                    MaterialTheme
                        .typography
                        .bodySmall
            )

            Spacer(
                modifier =
                    Modifier.height(6.dp)
            )

            Text(
                "Static: ${result.staticRisk}"
            )

            Text(
                "Behavior: " +
                        "${result.behaviorScore}/100"
            )

            Text(
                "Network: " +
                        formatBytes(
                            result.networkBytes
                        )
            )

            Text(
                "Overall: " +
                        "${result.overallScore}/100"
            )
        }
    }
}


// ==========================================================
// NETWORK USAGE CARD
// ==========================================================

@Composable
fun NetworkUsageCard(
    usage: AppNetworkUsage
) {

    Card(

        modifier =
            Modifier.fillMaxWidth()
    ) {

        Column(

            modifier =
                Modifier.padding(12.dp)
        ) {

            Text(

                text =
                    usage.appName,

                fontWeight =
                    FontWeight.Bold
            )

            Text(

                text =
                    usage.packageName,

                style =
                    MaterialTheme
                        .typography
                        .bodySmall
            )

            Spacer(
                modifier =
                    Modifier.height(6.dp)
            )

            Text(
                "Downloaded: " +
                        formatBytes(
                            usage.rxBytes
                        )
            )

            Text(
                "Uploaded: " +
                        formatBytes(
                            usage.txBytes
                        )
            )

            Text(
                "Total: " +
                        formatBytes(
                            usage.totalBytes
                        )
            )
        }
    }
}


// ==========================================================
// RISK ICON
// ==========================================================

fun getRiskIcon(
    riskLevel: String
): String {

    return when (riskLevel) {

        "HIGH",
        "HIGH RISK" ->
            "🔴"

        "SUSPICIOUS" ->
            "🟠"

        "LOW",
        "LOW RISK" ->
            "🟡"

        else ->
            "🟢"
    }
}


// ==========================================================
// FORMAT BYTES
// ==========================================================

fun formatBytes(
    bytes: Long
): String {

    return when {

        bytes >=
                1024L * 1024L ->

            String.format(
                "%.2f MB",
                bytes /
                        (1024.0 * 1024.0)
            )

        bytes >=
                1024L ->

            String.format(
                "%.2f KB",
                bytes / 1024.0
            )

        else ->
            "$bytes B"
    }
}