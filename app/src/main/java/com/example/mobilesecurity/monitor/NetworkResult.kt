package com.example.mobilesecurity.monitor

data class NetworkResult(
    val totalPackets: Int,
    val tcpPackets: Int,
    val udpPackets: Int,
    val icmpPackets: Int,
    val totalBytes: Long,
    val uniqueDestinations: Int,
    val destinations: List<String>,
    val networkScore: Int
)