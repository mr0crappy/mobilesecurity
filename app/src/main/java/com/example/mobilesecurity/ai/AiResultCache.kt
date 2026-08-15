package com.example.mobilesecurity.ai

import android.content.Context
import org.json.JSONObject

class AiResultCache(
    context: Context
) {

    private val preferences =
        context.getSharedPreferences(
            "ai_result_cache",
            Context.MODE_PRIVATE
        )


    fun save(
        packageName: String,
        apkModifiedTime: Long,
        prediction: AiPrediction
    ) {

        val json =
            JSONObject().apply {

                put(
                    "apkModifiedTime",
                    apkModifiedTime
                )

                put(
                    "isMalicious",
                    prediction.isMalicious
                )

                put(
                    "confidence",
                    prediction.confidence
                )

                put(
                    "benignProbability",
                    prediction.benignProbability
                )

                put(
                    "maliciousProbability",
                    prediction.maliciousProbability
                )
            }

        preferences
            .edit()
            .putString(
                packageName,
                json.toString()
            )
            .apply()
    }


    fun get(
        packageName: String,
        apkModifiedTime: Long
    ): AiPrediction? {

        val stored =
            preferences.getString(
                packageName,
                null
            )
                ?: return null

        return try {

            val json =
                JSONObject(stored)

            val cachedModifiedTime =
                json.getLong(
                    "apkModifiedTime"
                )

            // APK hasn't changed
            if (
                cachedModifiedTime !=
                apkModifiedTime
            ) {
                return null
            }

            AiPrediction(

                isMalicious =
                    json.getBoolean(
                        "isMalicious"
                    ),

                confidence =
                    json.getDouble(
                        "confidence"
                    ).toFloat(),

                benignProbability =
                    json.getDouble(
                        "benignProbability"
                    ).toFloat(),

                maliciousProbability =
                    json.getDouble(
                        "maliciousProbability"
                    ).toFloat()
            )

        } catch (_: Exception) {

            null
        }
    }


    fun clear(
        packageName: String
    ) {

        preferences
            .edit()
            .remove(packageName)
            .apply()
    }


}