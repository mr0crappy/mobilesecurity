package com.example.mobilesecurity.monitor

class NetworkAnalyzer {

    private var totalPackets = 0

    private var tcpPackets = 0

    private var udpPackets = 0

    private var icmpPackets = 0

    private var totalBytes = 0L

    private val destinations =
        mutableSetOf<String>()

    fun processPacket(
        protocol: Int,
        destination: String,
        size: Int
    ) {

        totalPackets++

        totalBytes += size

        destinations.add(destination)

        when (protocol) {

            6 -> tcpPackets++

            17 -> udpPackets++

            1 -> icmpPackets++
        }
    }

    fun getResult(): NetworkResult {

        val score =
            calculateNetworkScore()

        return NetworkResult(
            totalPackets = totalPackets,

            tcpPackets = tcpPackets,

            udpPackets = udpPackets,

            icmpPackets = icmpPackets,

            totalBytes = totalBytes,

            uniqueDestinations =
                destinations.size,

            destinations =
                destinations.toList(),

            networkScore = score
        )
    }

    private fun calculateNetworkScore(): Int {

        var score = 0

        // Large number of unique destinations
        if (destinations.size > 50) {
            score += 30
        } else if (destinations.size > 20) {
            score += 15
        }

        // Very high packet activity
        if (totalPackets > 10000) {
            score += 30
        } else if (totalPackets > 5000) {
            score += 15
        }

        // Large amount of traffic
        if (totalBytes > 100L * 1024L * 1024L) {
            score += 30
        } else if (totalBytes > 50L * 1024L * 1024L) {
            score += 15
        }

        return score.coerceIn(0, 100)
    }

    fun reset() {

        totalPackets = 0

        tcpPackets = 0

        udpPackets = 0

        icmpPackets = 0

        totalBytes = 0

        destinations.clear()
    }
}