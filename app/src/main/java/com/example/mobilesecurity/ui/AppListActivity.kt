package com.example.mobilesecurity

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.lifecycleScope
import com.example.mobilesecurity.scanner.AppInfo
import com.example.mobilesecurity.scanner.AppScanner
import com.example.mobilesecurity.ui.AppListScreen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AppListActivity : ComponentActivity() {

    private var apps by mutableStateOf<List<AppInfo>>(emptyList())

    override fun onCreate(
        savedInstanceState: Bundle?
    ) {
        super.onCreate(savedInstanceState)

        setContent {

            AppListScreen(
                apps = apps,

                onAppClick = { app ->

                    val intent =
                        Intent(
                            this,
                            AppDetailsActivity::class.java
                        )

                    intent.putExtra(
                        "packageName",
                        app.packageName
                    )

                    startActivity(intent)
                },

                onBack = {
                    finish()
                }
            )
        }

        // =========================================
        // SCAN IN BACKGROUND
        // =========================================

        lifecycleScope.launch {

            val scannedApps =
                withContext(Dispatchers.IO) {

                    AppScanner(
                        this@AppListActivity
                    ).scanApps()
                }

            // This runs back on the Main thread.
            // Updating Compose state here refreshes the UI.

            apps = scannedApps
        }
    }
}