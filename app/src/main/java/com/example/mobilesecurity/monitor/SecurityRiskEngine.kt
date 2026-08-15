package com.example.mobilesecurity.monitor

class SecurityRiskEngine {

    fun calculateRisk(
        appName: String,
        packageName: String,
        staticRisk: String,
        behaviorScore: Int,
        networkBytes: Long
    ): AppSecurityResult {

        var score = 0

        // -----------------------------
        // STATIC APP RISK
        // -----------------------------

        when (staticRisk) {

            "SAFE" -> {
                score += 0
            }

            "LOW RISK" -> {
                score += 15
            }

            "SUSPICIOUS" -> {
                score += 35
            }

            "HIGH RISK" -> {
                score += 60
            }
        }

        // -----------------------------
        // BEHAVIOR
        // -----------------------------

        score +=
            (behaviorScore * 0.30)
                .toInt()

        // -----------------------------
        // NETWORK
        // -----------------------------

        val networkScore =
            calculateNetworkScore(
                networkBytes
            )

        score +=
            (networkScore * 0.20)
                .toInt()

        score =
            score.coerceIn(
                0,
                100
            )

        val riskLevel =
            when {

                score >= 70 ->
                    "HIGH"

                score >= 40 ->
                    "SUSPICIOUS"

                score >= 20 ->
                    "LOW"

                else ->
                    "SAFE"
            }

        return AppSecurityResult(
            packageName =
                packageName,

            appName =
                appName,

            staticRisk =
                staticRisk,

            behaviorScore =
                behaviorScore,

            networkBytes =
                networkBytes,

            overallScore =
                score,

            riskLevel =
                riskLevel
        )
    }

    private fun calculateNetworkScore(
        bytes: Long
    ): Int {

        val mb =
            bytes /
                    (1024.0 * 1024.0)

        return when {

            mb > 500 ->
                100

            mb > 200 ->
                70

            mb > 100 ->
                40

            mb > 50 ->
                20

            else ->
                0
        }
    }
}