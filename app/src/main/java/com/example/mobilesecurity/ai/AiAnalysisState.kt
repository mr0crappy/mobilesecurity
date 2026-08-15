package com.example.mobilesecurity.ai

sealed class AiAnalysisState {

    data object Loading : AiAnalysisState()

    data class Success(
        val prediction: AiPrediction
    ) : AiAnalysisState()

    data class Error(
        val message: String
    ) : AiAnalysisState()
}