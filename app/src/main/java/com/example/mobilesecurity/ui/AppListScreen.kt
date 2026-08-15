package com.example.mobilesecurity.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.mobilesecurity.scanner.AppInfo

import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding

import androidx.compose.foundation.layout.height

@Composable
fun AppListScreen(
    apps: List<AppInfo>,
    onAppClick: (AppInfo) -> Unit,
    onBack: () -> Unit
) {

    Column(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(
                WindowInsets.statusBars
            )
            .padding(16.dp)
    ) {

        // Back button

        TextButton(
            onClick = onBack
        ) {

            Text("← Dashboard")
        }


        Text(
            text = "Installed Apps",

            style =
                MaterialTheme
                    .typography
                    .headlineMedium,

            fontWeight =
                FontWeight.Bold
        )

        Text(
            text =
                "${apps.size} applications",

            style =
                MaterialTheme
                    .typography
                    .bodyMedium,

            modifier =
                Modifier.padding(
                    top = 4.dp
                )
        )

        Spacer(
            modifier =
                Modifier.size(16.dp)
        )


        LazyColumn(

            modifier =
                Modifier.fillMaxSize(),

            verticalArrangement =
                Arrangement.spacedBy(8.dp)
        ) {

            items(

                items = apps,

                key = {
                    it.packageName
                }

            ) { app ->

                AppListItem(

                    app = app,

                    onClick = {
                        onAppClick(app)
                    }
                )
            }
        }
    }
}


@Composable
private fun AppListItem(
    app: AppInfo,
    onClick: () -> Unit
) {

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable {
                onClick()
            }
    ) {

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),

            verticalAlignment =
                Alignment.CenterVertically
        ) {

            // =========================================
            // APP ICON
            // =========================================

            AppIcon(
                packageName = app.packageName,
                modifier = Modifier.size(48.dp)
            )


            Spacer(
                modifier = Modifier.width(12.dp)
            )


            // =========================================
            // APP INFORMATION
            // =========================================

            Column(
                modifier = Modifier.weight(1f)
            ) {

                Text(
                    text = app.name,

                    fontWeight =
                        FontWeight.Bold,

                    maxLines = 1
                )

                Text(
                    text = app.packageName,

                    style =
                        MaterialTheme
                            .typography
                            .bodySmall,

                    maxLines = 1
                )

                Spacer(
                    modifier = Modifier.height(4.dp)
                )

                Text(
                    text =
                        "${app.permissionCount} permissions",

                    style =
                        MaterialTheme
                            .typography
                            .bodySmall
                )

                Text(
                    text =
                        "AI: ${
                            String.format(
                                "%.1f",
                                app.aiBenignProbability * 100f
                            )
                        }% benign",

                    style =
                        MaterialTheme
                            .typography
                            .bodySmall,

                    fontWeight =
                        FontWeight.Medium
                )
            }


            // =========================================
            // RISK + AI
            // =========================================

            Column(
                horizontalAlignment =
                    Alignment.End
            ) {

                Text(
                    text =
                        getRiskIcon(
                            app.riskLevel
                        ),

                    style =
                        MaterialTheme
                            .typography
                            .titleLarge
                )

                Text(
                    text =
                        app.riskLevel,

                    style =
                        MaterialTheme
                            .typography
                            .labelSmall,

                    fontWeight =
                        FontWeight.Bold
                )


                Spacer(
                    modifier =
                        Modifier.height(4.dp)
                )


                Text(
                    text =
                        if (app.aiMalicious) {
                            "AI: MALICIOUS"
                        } else {
                            "AI: BENIGN"
                        },

                    style =
                        MaterialTheme
                            .typography
                            .labelSmall,

                    fontWeight =
                        FontWeight.Bold
                )
            }
        }
    }
}
