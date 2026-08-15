package com.example.mobilesecurity

import android.os.Bundle

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent

import com.example.mobilesecurity.monitor.BehaviorMonitor
import com.example.mobilesecurity.monitor.NetworkUsageMonitor
import com.example.mobilesecurity.scanner.AppScanner
import com.example.mobilesecurity.ui.Dashboard

class MainActivity : ComponentActivity() {

    private lateinit var scanner: AppScanner

    private lateinit var behaviorMonitor: BehaviorMonitor

    private lateinit var networkUsageMonitor: NetworkUsageMonitor


    override fun onCreate(
        savedInstanceState: Bundle?
    ) {

        super.onCreate(savedInstanceState)


        scanner =
            AppScanner(this)

        behaviorMonitor =
            BehaviorMonitor(this)

        networkUsageMonitor =
            NetworkUsageMonitor(this)


        setContent {

            Dashboard(

                scanner =
                    scanner,

                behaviorMonitor =
                    behaviorMonitor,

                networkUsageMonitor =
                    networkUsageMonitor,

                onStartVpn = {
                    // Keep your existing VPN start code
                },

                onStopVpn = {
                    // Keep your existing VPN stop code
                }
            )
        }
    }
}