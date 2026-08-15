package com.example.mobilesecurity.monitor

data class NetworkMonitorState(
    val isRunning: Boolean = false,
    val totalPackets: Int = 0,
    val tcpPackets: Int = 0,
    val udpPackets: Int = 0,
    val totalBytes: Long = 0,
    val uniqueDestinations: Int = 0,
    val networkScore: Int = 0,
    val dnsDomains: List<String> = emptyList()
)