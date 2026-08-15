package com.example.mobilesecurity

import android.os.Bundle
import android.util.Log

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.lifecycleScope

import com.example.mobilesecurity.ai.AiAnalysisState
import com.example.mobilesecurity.ai.AiModel
import com.example.mobilesecurity.scanner.ApkFeatureExtractor
import com.example.mobilesecurity.scanner.AppInfo
import com.example.mobilesecurity.scanner.AppScanner
import com.example.mobilesecurity.ui.AppDetailsScreen

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AppDetailsActivity : ComponentActivity() {

    private lateinit var aiModel: AiModel

    private var analysisJob: Job? = null

    private var aiState by mutableStateOf<AiAnalysisState>(
        AiAnalysisState.Loading
    )

    private var app by mutableStateOf<AppInfo?>(null)

    override fun onCreate(
        savedInstanceState: Bundle?
    ) {
        super.onCreate(savedInstanceState)

        val packageName =
            intent.getStringExtra("packageName")

        if (packageName == null) {
            finish()
            return
        }

        // =================================================
        // AI MODEL
        // =================================================

        aiModel = AiModel(this)

        // =================================================
        // UI
        // =================================================

        setContent {

            val currentApp = app

            if (currentApp != null) {

                AppDetailsScreen(

                    app = currentApp,

                    aiState = aiState,

                    onRescan = {
                        if (
                            aiState !is
                                    AiAnalysisState.Loading
                        ) {
                            analyzeApp(packageName)
                        }
                    },

                    onBack = {
                        finish()
                    }
                )
            }
        }

        // =================================================
        // INITIAL SCAN
        // =================================================

        analyzeApp(packageName)
    }


    // =====================================================
    // ANALYZE APP
    // =====================================================

    private fun analyzeApp(
        packageName: String
    ) {

        // Cancel previous scan
        analysisJob?.cancel()

        aiState =
            AiAnalysisState.Loading

        analysisJob =
            lifecycleScope.launch {

                try {

                    // =====================================
                    // BASIC APP INFORMATION
                    // =====================================

                    val selectedApp =
                        withContext(
                            Dispatchers.IO
                        ) {

                            AppScanner(
                                this@AppDetailsActivity
                            ).scanSingleApp(
                                packageName
                            )
                        }

                    if (selectedApp == null) {

                        aiState =
                            AiAnalysisState.Error(
                                "Unable to read application information."
                            )

                        return@launch
                    }

                    // Set initial app information
                    app =
                        selectedApp


                    // =====================================
                    // FEATURE EXTRACTION + AI
                    // =====================================

                    val prediction =
                        withContext(
                            Dispatchers.Default
                        ) {

                            val extractor =
                                ApkFeatureExtractor(
                                    this@AppDetailsActivity
                                )

                            // Extract features ONCE
                            val features =
                                extractor.extract(
                                    packageName
                                )


                            // =================================
                            // FEATURE VALIDATION
                            // =================================

                            require(
                                features.size ==
                                        ApkFeatureExtractor
                                            .FEATURE_NAMES
                                            .size
                            ) {

                                "Feature count mismatch: " +
                                        "${features.size} != " +
                                        "${ApkFeatureExtractor.FEATURE_NAMES.size}"
                            }


                            // =================================
                            // ACTIVE FEATURE COUNT
                            // =================================

                            val activeFeatureCount =
                                features.count {
                                    it > 0.5f
                                }

                            Log.d(
                                "AI_VALIDATION",
                                "FEATURE COUNT = ${features.size}"
                            )

                            Log.d(
                                "AI_VALIDATION",
                                "EXPECTED COUNT = ${
                                    ApkFeatureExtractor
                                        .FEATURE_NAMES
                                        .size
                                }"
                            )

                            Log.d(
                                "AI_VALIDATION",
                                "ACTIVE FEATURES = " +
                                        "$activeFeatureCount / " +
                                        "${features.size}"
                            )


                            // =================================
                            // FEATURE DETAILS
                            // =================================

                            for (
                            i in features.indices
                            ) {

                                Log.d(
                                    "AI_VALIDATION",
                                    "$i | " +
                                            "${ApkFeatureExtractor.FEATURE_NAMES[i]} | " +
                                            "${features[i]}"
                                )
                            }


                            // =================================
                            // ONNX PREDICTION
                            // =================================

                            aiModel.predict(
                                features
                            )
                        }


                    // =====================================
                    // UPDATE ACTIVE FEATURE COUNT
                    // =====================================

                    val extractor =
                        ApkFeatureExtractor(
                            this@AppDetailsActivity
                        )

                    val features =
                        withContext(
                            Dispatchers.Default
                        ) {
                            extractor.extract(
                                packageName
                            )
                        }

                    val activeFeatureCount =
                        features.count {
                            it > 0.5f
                        }


                    app =
                        app?.copy(
                            activeAiFeatures =
                                activeFeatureCount
                        )


                    // =====================================
                    // UPDATE AI STATE
                    // =====================================

                    aiState =
                        AiAnalysisState.Success(
                            prediction
                        )

                } catch (
                    e: CancellationException
                ) {

                    // Scan was cancelled.
                    // Don't show an error.

                    throw e

                } catch (e: Exception) {

                    Log.e(
                        "AI_ANALYSIS",
                        "Failed to analyze $packageName",
                        e
                    )

                    aiState =
                        AiAnalysisState.Error(
                            e.message
                                ?: "Unable to analyze application"
                        )
                }
            }
    }


    // =====================================================
    // DESTROY
    // =====================================================

    override fun onDestroy() {

        analysisJob?.cancel()

        if (::aiModel.isInitialized) {
            aiModel.close()
        }

        super.onDestroy()
    }
}