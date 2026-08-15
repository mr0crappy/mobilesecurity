package com.example.mobilesecurity.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll

import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton

import androidx.compose.runtime.Composable

import com.example.mobilesecurity.scanner.ApkFeatureExtractor

import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

import com.example.mobilesecurity.ai.AiAnalysisState
import com.example.mobilesecurity.scanner.AppInfo


@Composable
fun AppDetailsScreen(
    app: AppInfo,
    aiState: AiAnalysisState,
    onRescan: () -> Unit,
    onBack: () -> Unit
) {

    Column(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(
                WindowInsets.statusBars
            )
            .verticalScroll(
                rememberScrollState()
            )
            .padding(16.dp)
    ) {

        // =====================================================
        // BACK
        // =====================================================

        TextButton(
            onClick = onBack
        ) {
            Text("← Back")
        }

        Spacer(
            modifier = Modifier.height(8.dp)
        )


        // =====================================================
        // APP HEADER
        // =====================================================

        Card(
            modifier = Modifier.fillMaxWidth()
        ) {

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(18.dp),

                verticalAlignment =
                    Alignment.CenterVertically
            ) {

                AppIcon(
                    packageName = app.packageName,
                    modifier = Modifier.size(64.dp)
                )

                Spacer(
                    modifier = Modifier.width(14.dp)
                )

                Column(
                    modifier = Modifier.weight(1f)
                ) {

                    Text(
                        text = app.name,
                        style =
                            MaterialTheme
                                .typography
                                .titleLarge,
                        fontWeight =
                            FontWeight.Bold
                    )

                    Spacer(
                        modifier = Modifier.height(3.dp)
                    )

                    Text(
                        text = app.packageName,
                        style =
                            MaterialTheme
                                .typography
                                .bodySmall
                    )

                    Spacer(
                        modifier = Modifier.height(3.dp)
                    )

                    Text(
                        text =
                            "Version: ${
                                app.versionName ?: "Unknown"
                            }",
                        style =
                            MaterialTheme
                                .typography
                                .bodySmall
                    )
                }
            }
        }


        Spacer(
            modifier = Modifier.height(12.dp)
        )


        // =====================================================
        // AI SECURITY ANALYSIS
        // =====================================================

        Card(
            modifier = Modifier.fillMaxWidth()
        ) {

            Column(
                modifier = Modifier.padding(18.dp)
            ) {

                Text(
                    text = "AI Security Analysis",
                    style =
                        MaterialTheme
                            .typography
                            .titleMedium,
                    fontWeight =
                        FontWeight.Bold
                )

                Spacer(
                    modifier = Modifier.height(14.dp)
                )


                when (val state = aiState) {

                    // =================================================
                    // LOADING
                    // =================================================

                    AiAnalysisState.Loading -> {

                        Text(
                            text = "⏳ Analyzing application...",
                            style =
                                MaterialTheme
                                    .typography
                                    .bodyLarge,
                            fontWeight =
                                FontWeight.Bold
                        )

                        Spacer(
                            modifier = Modifier.height(8.dp)
                        )

                        LinearProgressIndicator(
                            modifier =
                                Modifier.fillMaxWidth()
                        )

                        Spacer(
                            modifier = Modifier.height(8.dp)
                        )

                        Text(
                            text =
                                "The AI model is analyzing the APK.",
                            style =
                                MaterialTheme
                                    .typography
                                    .bodySmall
                        )
                    }


                    // =================================================
                    // SUCCESS
                    // =================================================

                    is AiAnalysisState.Success -> {

                        val prediction =
                            state.prediction

                        val confidence =
                            prediction.confidence * 100f

                        val classification =
                            if (
                                prediction.isMalicious
                            ) {
                                "MALICIOUS"
                            } else {
                                "BENIGN"
                            }

                        val icon =
                            if (
                                prediction.isMalicious
                            ) {
                                "🔴"
                            } else {
                                "🟢"
                            }


                        Text(
                            text =
                                "$icon $classification",
                            style =
                                MaterialTheme
                                    .typography
                                    .headlineSmall,
                            fontWeight =
                                FontWeight.Bold
                        )

                        Spacer(
                            modifier =
                                Modifier.height(10.dp)
                        )


                        LinearProgressIndicator(
                            progress = {
                                prediction.confidence
                            },
                            modifier =
                                Modifier
                                    .fillMaxWidth()
                                    .height(8.dp)
                        )

                        Spacer(
                            modifier =
                                Modifier.height(12.dp)
                        )


                        DetailRow(
                            title = "Confidence",
                            value =
                                String.format(
                                    "%.1f%%",
                                    confidence
                                )
                        )

                        DetailRow(
                            title = "Benign Probability",
                            value =
                                String.format(
                                    "%.1f%%",
                                    prediction
                                        .benignProbability *
                                            100f
                                )
                        )

                        DetailRow(
                            title = "Malicious Probability",
                            value =
                                String.format(
                                    "%.1f%%",
                                    prediction
                                        .maliciousProbability *
                                            100f
                                )
                        )

                        DetailRow(
                            title = "Active AI Features",
                            value =
                                "${app.activeAiFeatures} / ${
                                    ApkFeatureExtractor.FEATURE_NAMES.size
                                }"
                        )


                        Spacer(
                            modifier =
                                Modifier.height(16.dp)
                        )


                        Button(
                            onClick = onRescan,
                            modifier =
                                Modifier.fillMaxWidth()
                        ) {

                            Text(
                                "↻ Rescan with AI"
                            )
                        }
                    }


                    // =================================================
                    // ERROR
                    // =================================================

                    is AiAnalysisState.Error -> {

                        Text(
                            text = "⚠ AI Analysis Failed",
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

                        Text(
                            text = state.message,
                            style =
                                MaterialTheme
                                    .typography
                                    .bodySmall
                        )

                        Spacer(
                            modifier =
                                Modifier.height(14.dp)
                        )

                        Button(
                            onClick = onRescan,
                            modifier =
                                Modifier.fillMaxWidth()
                        ) {

                            Text(
                                "↻ Try Again"
                            )
                        }
                    }
                }
            }
        }


        Spacer(
            modifier = Modifier.height(12.dp)
        )


        // =====================================================
        // FINAL SECURITY VERDICT
        // =====================================================

        Card(
            modifier = Modifier.fillMaxWidth()
        ) {

            Column(
                modifier = Modifier.padding(18.dp)
            ) {

                Text(
                    text = "Final Security Verdict",
                    style =
                        MaterialTheme
                            .typography
                            .titleMedium,
                    fontWeight =
                        FontWeight.Bold
                )

                Spacer(
                    modifier =
                        Modifier.height(14.dp)
                )


                when (val state = aiState) {

                    AiAnalysisState.Loading -> {

                        Text(
                            text = "⏳ ANALYZING",
                            style =
                                MaterialTheme
                                    .typography
                                    .headlineSmall,
                            fontWeight =
                                FontWeight.Bold
                        )

                        Spacer(
                            modifier =
                                Modifier.height(8.dp)
                        )

                        Text(
                            text =
                                "Waiting for the AI analysis to complete."
                        )
                    }


                    is AiAnalysisState.Success -> {

                        val prediction =
                            state.prediction

                        val finalRisk =
                            getFinalRisk(
                                staticRiskScore =
                                    app.riskScore,
                                maliciousProbability =
                                    prediction
                                        .maliciousProbability
                            )

                        Text(
                            text =
                                "${getFinalRiskIcon(finalRisk)} $finalRisk",
                            style =
                                MaterialTheme
                                    .typography
                                    .headlineSmall,
                            fontWeight =
                                FontWeight.Bold
                        )

                        Spacer(
                            modifier =
                                Modifier.height(14.dp)
                        )

                        DetailRow(
                            title = "Static Risk",
                            value =
                                "${app.riskScore}/100"
                        )

                        DetailRow(
                            title = "AI Confidence",
                            value =
                                String.format(
                                    "%.1f%%",
                                    prediction.confidence *
                                            100f
                                )
                        )

                        DetailRow(
                            title = "Malicious Probability",
                            value =
                                String.format(
                                    "%.1f%%",
                                    prediction
                                        .maliciousProbability *
                                            100f
                                )
                        )

                        DetailRow(
                            title = "Benign Probability",
                            value =
                                String.format(
                                    "%.1f%%",
                                    prediction
                                        .benignProbability *
                                            100f
                                )
                        )
                    }


                    is AiAnalysisState.Error -> {

                        Text(
                            text = "⚠ ANALYSIS INCOMPLETE",
                            style =
                                MaterialTheme
                                    .typography
                                    .headlineSmall,
                            fontWeight =
                                FontWeight.Bold
                        )

                        Spacer(
                            modifier =
                                Modifier.height(8.dp)
                        )

                        Text(
                            text =
                                "The final security verdict could not be calculated."
                        )
                    }
                }
            }
        }


        Spacer(
            modifier = Modifier.height(12.dp)
        )


        // =====================================================
        // STATIC RISK
        // =====================================================

        Card(
            modifier = Modifier.fillMaxWidth()
        ) {

            Column(
                modifier = Modifier.padding(18.dp)
            ) {

                Text(
                    text =
                        "${getRiskIcon(app.riskLevel)} " +
                                app.riskLevel,
                    style =
                        MaterialTheme
                            .typography
                            .headlineSmall,
                    fontWeight =
                        FontWeight.Bold
                )

                Spacer(
                    modifier =
                        Modifier.height(8.dp)
                )

                Text(
                    text =
                        "Risk Score: ${app.riskScore}/100"
                )

                Spacer(
                    modifier =
                        Modifier.height(12.dp)
                )

                Text(
                    text =
                        getRiskExplanation(app),
                    style =
                        MaterialTheme
                            .typography
                            .bodyMedium
                )
            }
        }


        Spacer(
            modifier =
                Modifier.height(12.dp)
        )


        // =====================================================
        // SECURITY STATISTICS
        // =====================================================

        Card(
            modifier =
                Modifier.fillMaxWidth()
        ) {

            Column(
                modifier =
                    Modifier.padding(18.dp)
            ) {

                Text(
                    text =
                        "Security Statistics",
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

                DetailRow(
                    title = "Total Permissions",
                    value =
                        app.permissionCount.toString()
                )

                DetailRow(
                    title = "Dangerous Permissions",
                    value =
                        app.dangerousPermissionCount
                            .toString()
                )

                DetailRow(
                    title = "Static Risk Score",
                    value =
                        "${app.riskScore}/100"
                )
            }
        }


        Spacer(
            modifier =
                Modifier.height(12.dp)
        )


        // =====================================================
        // PERMISSIONS
        // =====================================================

        Card(
            modifier =
                Modifier.fillMaxWidth()
        ) {

            Column(
                modifier =
                    Modifier.padding(18.dp)
            ) {

                Text(
                    text =
                        "Requested Permissions",
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

                if (app.permissions.isEmpty()) {

                    Text(
                        text =
                            "No requested permissions."
                    )

                } else {

                    app.permissions.forEach { permission ->

                        val dangerous =
                            isDangerousPermissionForUi(
                                permission
                            )

                        Text(
                            text =
                                if (dangerous) {
                                    "⚠️ " +
                                            permission
                                                .removePrefix(
                                                    "android.permission."
                                                )
                                } else {
                                    "• " +
                                            permission
                                                .removePrefix(
                                                    "android.permission."
                                                )
                                },

                            fontWeight =
                                if (dangerous) {
                                    FontWeight.Bold
                                } else {
                                    FontWeight.Normal
                                },

                            style =
                                MaterialTheme
                                    .typography
                                    .bodySmall,

                            modifier =
                                Modifier.padding(
                                    vertical = 3.dp
                                )
                        )
                    }
                }
            }
        }


        Spacer(
            modifier =
                Modifier.height(20.dp)
        )
    }
}


// =============================================================
// DETAIL ROW
// =============================================================

@Composable
private fun DetailRow(
    title: String,
    value: String
) {

    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .padding(
                    vertical = 5.dp
                ),

        horizontalArrangement =
            Arrangement.SpaceBetween
    ) {

        Text(
            text = title
        )

        Text(
            text = value,
            fontWeight =
                FontWeight.Bold
        )
    }
}


// =============================================================
// STATIC RISK EXPLANATION
// =============================================================

private fun getRiskExplanation(
    app: AppInfo
): String {

    return when {

        app.riskScore >= 80 ->
            "This application has several potentially " +
                    "sensitive capabilities. Review its " +
                    "permissions carefully."

        app.riskScore >= 60 ->
            "This application requests multiple sensitive " +
                    "permissions or capabilities. Further " +
                    "investigation is recommended."

        app.riskScore >= 30 ->
            "This application has some sensitive permissions, " +
                    "but the current static analysis does not " +
                    "indicate a high level of risk."

        else ->
            "No significant risk indicators were detected " +
                    "by the current static analysis."
    }
}


// =============================================================
// DANGEROUS PERMISSION CHECK
// =============================================================

private fun isDangerousPermissionForUi(
    permission: String
): Boolean {

    return permission in setOf(

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

        "android.permission.READ_PHONE_STATE"
    )
}


// =============================================================
// FINAL RISK
// =============================================================

private fun getFinalRisk(
    staticRiskScore: Int,
    maliciousProbability: Float
): String {

    val aiRisk =
        maliciousProbability * 100f

    return when {

        aiRisk >= 80f ->
            "HIGH"

        aiRisk >= 60f ||
                staticRiskScore >= 80 ->
            "SUSPICIOUS"

        aiRisk >= 30f ||
                staticRiskScore >= 60 ->
            "LOW"

        else ->
            "SAFE"
    }
}


// =============================================================
// FINAL RISK ICON
// =============================================================

private fun getFinalRiskIcon(
    risk: String
): String {

    return when (risk) {

        "HIGH" ->
            "🔴"

        "SUSPICIOUS" ->
            "🟠"

        "LOW" ->
            "🟡"

        else ->
            "🟢"
    }
}


// =============================================================
// STATIC RISK ICON
// =============================================================

