package com.example.mobilesecurity.ai

import android.content.Context
import android.util.Log

import ai.onnxruntime.OnnxMap
import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession

import com.example.mobilesecurity.scanner.ApkFeatureExtractor

import java.nio.FloatBuffer

data class AiPrediction(
    val isMalicious: Boolean,
    val confidence: Float,
    val benignProbability: Float,
    val maliciousProbability: Float
)

class AiModel(
    private val context: Context
) {

    private val environment =
        OrtEnvironment.getEnvironment()

    private val session: OrtSession

    init {

        val modelBytes =
            context.assets
                .open("mobile_security_model_v6.onnx")
                .use {
                    it.readBytes()
                }

        session =
            environment.createSession(
                modelBytes,
                OrtSession.SessionOptions()
            )
    }

    fun predict(
        features: FloatArray
    ): AiPrediction {

        require(
            features.size ==
                    ApkFeatureExtractor.FEATURE_NAMES.size
        ) {
            "Expected ${
                ApkFeatureExtractor.FEATURE_NAMES.size
            } features but got ${
                features.size
            }"
        }

        val inputTensor =
            OnnxTensor.createTensor(
                environment,
                FloatBuffer.wrap(features),
                longArrayOf(
                    1,
                    features.size.toLong()
                )
            )

        inputTensor.use { tensor ->

            val inputName =
                session.inputNames.first()

            session.run(
                mapOf(
                    inputName to tensor
                )
            ).use { result ->

                // -----------------------------------------
                // OUTPUT 0 — PREDICTED CLASS
                // -----------------------------------------

                val label =
                    result[0].value

                val isMalicious =
                    when (label) {

                        is LongArray ->
                            label[0] == 1L

                        is IntArray ->
                            label[0] == 1

                        is Array<*> ->
                            label[0].toString() == "1"

                        is List<*> ->
                            label[0].toString() == "1"

                        else ->
                            label.toString() == "1"
                    }


                // -----------------------------------------
                // OUTPUT 1 — CLASS PROBABILITIES
                // -----------------------------------------

                var benignProbability = 0f
                var maliciousProbability = 0f

                val probabilityOutput =
                    result[1].value


                /*
                 * sklearn RandomForest exported by
                 * skl2onnx produces a sequence/list
                 * containing an OnnxMap.
                 */

                if (probabilityOutput is List<*>) {

                    if (probabilityOutput.isNotEmpty()) {

                        val first =
                            probabilityOutput[0]

                        if (first is OnnxMap) {

                            val probabilityMap =
                                first.getValue()

                            for (
                            entry
                            in probabilityMap.entries
                            ) {

                                val key =
                                    entry.key

                                val value =
                                    entry.value


                                val probability =
                                    when (value) {

                                        is Number ->
                                            value.toFloat()

                                        else ->
                                            0f
                                    }


                                when (key) {

                                    0L ->
                                        benignProbability =
                                            probability

                                    1L ->
                                        maliciousProbability =
                                            probability
                                }
                            }
                        }
                    }
                }


                // -----------------------------------------
                // CONFIDENCE
                // -----------------------------------------

                val confidence =
                    if (isMalicious) {

                        maliciousProbability

                    } else {

                        benignProbability
                    }


                // -----------------------------------------
                // LOGGING
                // -----------------------------------------

                Log.d(
                    "AI_MODEL",
                    "Benign probability = $benignProbability"
                )

                Log.d(
                    "AI_MODEL",
                    "Malicious probability = $maliciousProbability"
                )

                Log.d(
                    "AI_MODEL",
                    "Malicious = $isMalicious"
                )

                Log.d(
                    "AI_MODEL",
                    "Confidence = $confidence"
                )


                return AiPrediction(

                    isMalicious =
                        isMalicious,

                    confidence =
                        confidence,

                    benignProbability =
                        benignProbability,

                    maliciousProbability =
                        maliciousProbability
                )
            }
        }
    }

    fun close() {

        session.close()

        environment.close()
    }
}