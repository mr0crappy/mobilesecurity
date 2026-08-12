package com.example.mobilesecurity

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent

import com.example.mobilesecurity.monitor.BehaviorMonitor
import com.example.mobilesecurity.scanner.AppScanner
import com.example.mobilesecurity.ui.Dashboard

class MainActivity : ComponentActivity() {

    override fun onCreate(
        savedInstanceState: Bundle?
    ) {
        super.onCreate(savedInstanceState)

        val scanner =
            AppScanner(this)

        val behaviorMonitor =
            BehaviorMonitor(this)

        setContent {

            Dashboard(
                scanner = scanner,
                behaviorMonitor = behaviorMonitor
            )
        }
    }
}