package com.example.mobilesecurity.monitor

class DnsAnalyzer {

    private val domains =
        mutableSetOf<String>()

    private val requestCounts =
        mutableMapOf<String, Int>()

    fun recordDomain(domain: String) {

        val normalized =
            domain.lowercase().trim()

        if (normalized.isEmpty()) {
            return
        }

        domains.add(normalized)

        requestCounts[normalized] =
            (requestCounts[normalized] ?: 0) + 1
    }

    fun getDomains(): List<String> {
        return domains.toList()
    }

    fun getRequestCount(
        domain: String
    ): Int {

        return requestCounts[domain] ?: 0
    }

    fun getUniqueDomainCount(): Int {
        return domains.size
    }
}