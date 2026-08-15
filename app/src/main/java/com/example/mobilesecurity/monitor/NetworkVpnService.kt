package com.example.mobilesecurity.monitor

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

class NetworkVpnService : VpnService() {

    companion object {

        const val ACTION_STOP =
            "com.example.mobilesecurity.STOP_VPN"

        private val _state =
            MutableStateFlow(
                NetworkMonitorState()
            )

        val state: StateFlow<NetworkMonitorState>
            get() = _state
    }

    private var vpnInterface: ParcelFileDescriptor? = null

    private var packetThread: Thread? = null

    private val networkAnalyzer =
        NetworkAnalyzer()

    private val dnsAnalyzer =
        DnsAnalyzer()

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int
    ): Int {

        // Stop request
        if (intent?.action == ACTION_STOP) {

            Log.d(
                "NetworkMonitor",
                "Stop request received"
            )

            stopVpn()

            return START_NOT_STICKY
        }

        startVpn()

        return START_STICKY
    }

    private fun startVpn() {

        try {

            vpnInterface?.close()

            vpnInterface = Builder()
                .setSession("Mobile Security")
                .addAddress(
                    "10.0.0.2",
                    32
                )
                .addRoute(
                    "10.0.0.0",
                    8
                )
                .setBlocking(true)
                .establish()

            if (vpnInterface == null) {

                Log.e(
                    "NetworkMonitor",
                    "Failed to establish VPN"
                )

                return
            }

            Log.d(
                "NetworkMonitor",
                "VPN started"
            )

            _state.value =
                NetworkMonitorState(
                    isRunning = true
                )

            startPacketReader()

        } catch (e: Exception) {

            Log.e(
                "NetworkMonitor",
                "Failed to start VPN",
                e
            )

            _state.value =
                NetworkMonitorState(
                    isRunning = false
                )

            stopSelf()
        }
    }

    private fun stopVpn() {

        Log.d(
            "NetworkMonitor",
            "Stopping VPN..."
        )

        packetThread?.interrupt()
        packetThread = null

        try {

            vpnInterface?.close()

        } catch (e: Exception) {

            Log.e(
                "NetworkMonitor",
                "Error closing VPN",
                e
            )
        }

        vpnInterface = null

        _state.value =
            NetworkMonitorState(
                isRunning = false
            )

        Log.d(
            "NetworkMonitor",
            "VPN stopped"
        )

        stopSelf()
    }

    private fun startPacketReader() {

        val descriptor =
            vpnInterface ?: return

        packetThread = Thread {

            try {

                FileInputStream(
                    descriptor.fileDescriptor
                ).use { input ->

                    val buffer =
                        ByteArray(32767)

                    while (
                        !Thread.currentThread()
                            .isInterrupted
                    ) {

                        val length =
                            input.read(buffer)

                        if (length > 0) {

                            try {

                                analyzePacket(
                                    buffer,
                                    length
                                )

                            } catch (e: Exception) {

                                Log.e(
                                    "NetworkMonitor",
                                    "Packet analysis error",
                                    e
                                )
                            }
                        }
                    }
                }

            } catch (e: Exception) {

                if (
                    !Thread.currentThread()
                        .isInterrupted
                ) {

                    Log.e(
                        "NetworkMonitor",
                        "Packet reader stopped",
                        e
                    )
                }
            }
        }

        packetThread?.start()
    }

    private fun analyzePacket(
        packet: ByteArray,
        length: Int
    ) {

        if (length < 20) {
            return
        }

        // IPv4 version
        val version =
            (packet[0].toInt() shr 4) and 0x0F

        if (version != 4) {
            return
        }

        // IPv4 header length
        val ipHeaderLength =
            (packet[0].toInt() and 0x0F) * 4

        if (
            ipHeaderLength < 20 ||
            ipHeaderLength > length
        ) {
            return
        }

        // Protocol
        val protocol =
            packet[9].toInt() and 0xFF

        // Destination IP
        val destination =
            "${packet[16].toInt() and 0xFF}." +
                    "${packet[17].toInt() and 0xFF}." +
                    "${packet[18].toInt() and 0xFF}." +
                    "${packet[19].toInt() and 0xFF}"

        // Analyze packet
        networkAnalyzer.processPacket(
            protocol = protocol,
            destination = destination,
            size = length
        )

        // Get current network statistics
        val result =
            networkAnalyzer.getResult()

        // Update UI state
        _state.value =
            NetworkMonitorState(
                isRunning = true,
                totalPackets = result.totalPackets,
                tcpPackets = result.tcpPackets,
                udpPackets = result.udpPackets,
                totalBytes = result.totalBytes,
                uniqueDestinations = result.uniqueDestinations,
                networkScore = result.networkScore,
                dnsDomains = dnsAnalyzer.getDomains()
            )

        Log.d(
            "NetworkMonitor",
            "PACKET protocol=$protocol " +
                    "destination=$destination " +
                    "size=$length"
        )

        // Only UDP can contain our DNS requests
        if (protocol != 17) {
            return
        }

        // UDP header = 8 bytes
        if (
            length < ipHeaderLength + 8
        ) {
            return
        }

        val udpHeaderStart =
            ipHeaderLength

        // Destination port
        val destinationPort =
            ((packet[udpHeaderStart + 2].toInt()
                    and 0xFF) shl 8) or
                    (packet[udpHeaderStart + 3].toInt()
                            and 0xFF)

        // DNS uses port 53
        if (destinationPort != 53) {
            return
        }

        val dnsStart =
            udpHeaderStart + 8

        if (dnsStart >= length) {
            return
        }

        val domain =
            parseDnsQuery(
                packet,
                dnsStart,
                length
            )

        if (domain != null) {

            dnsAnalyzer.recordDomain(
                domain
            )

            Log.d(
                "NetworkMonitor",
                "DNS: $domain"
            )
        }
    }

    private fun parseDnsQuery(
        packet: ByteArray,
        start: Int,
        length: Int
    ): String? {

        try {

            // DNS header = 12 bytes
            if (
                start < 0 ||
                start + 12 > length
            ) {
                return null
            }

            var position =
                start + 12

            val labels =
                mutableListOf<String>()

            var labelCount = 0

            while (
                position < length &&
                labelCount < 20
            ) {

                val labelLength =
                    packet[position].toInt() and 0xFF

                position++

                // End of domain
                if (labelLength == 0) {
                    break
                }

                // Compression pointer
                if (
                    (labelLength and 0xC0) == 0xC0
                ) {
                    break
                }

                // DNS label max = 63 bytes
                if (labelLength > 63) {
                    return null
                }

                if (
                    position + labelLength >
                    length
                ) {
                    return null
                }

                val label =
                    String(
                        packet,
                        position,
                        labelLength,
                        Charsets.US_ASCII
                    )

                if (label.isNotEmpty()) {
                    labels.add(label)
                }

                position += labelLength

                labelCount++
            }

            if (labels.isEmpty()) {
                return null
            }

            return labels.joinToString(".")

        } catch (e: Exception) {

            Log.e(
                "NetworkMonitor",
                "DNS parsing error",
                e
            )

            return null
        }
    }

    override fun onDestroy() {

        Log.d(
            "NetworkMonitor",
            "Service destroyed"
        )

        packetThread?.interrupt()
        packetThread = null

        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(
                "NetworkMonitor",
                "Error closing VPN",
                e
            )
        }

        vpnInterface = null

        _state.value =
            NetworkMonitorState(
                isRunning = false
            )

        super.onDestroy()
    }

    override fun onRevoke() {

        Log.d(
            "NetworkMonitor",
            "VPN revoked"
        )

        stopVpn()
    }
}