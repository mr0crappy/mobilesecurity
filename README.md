Mobile Security

An Android application that analyzes installed applications for
potential security risks using static APK analysis and an on-device
machine learning model.

Features

Scan installed applications

View application details and requested permissions

Count potentially dangerous permissions

Calculate a static risk score

Extract features from APK/DEX files

Analyze applications using an ONNX machine learning model

Display benign/malicious classification and confidence

Display benign and malicious probabilities

Show the number of active AI features

Rescan an individual application

Display a final security verdict combining static analysis and AI
analysis

How It Works

The application uses two layers of analysis.

Static Analysis

The scanner examines application permissions and assigns a risk score
based on potentially sensitive capabilities such as SMS, phone state,
location, Internet access, package installation, overlays, boot
completion, package visibility, and usage statistics.

Risk levels include:

SAFE

LOW RISK

SUSPICIOUS

HIGH RISK

AI Analysis

The application extracts exactly 50 features from the target APK/DEX
files.

These features are based on the feature set used by the Drebin dataset
and include permissions and API/class/method indicators.

The feature vector is passed to an ONNX Random Forest model.

The model returns:

Benign probability

Malicious probability

Classification

Confidence

The Android ONNX implementation was validated against the original
scikit-learn model with 100% prediction agreement on the validation
dataset.

Machine Learning Model

The model was trained using a small Drebin-based dataset.

Dataset distribution:

Class             Samples

Benign (B)          9,476
Malicious (S)       5,560
Total              15,036

The Android application uses the exported ONNX version of the model.

AI Features

The model expects exactly 50 features.

The Android extractor validates the generated feature vector before
inference and reports the number of active features, for example:

37 / 50 active features

Architecture

Android App
│
├── UI
│   ├── Dashboard
│   ├── App List
│   └── App Details
│
├── Scanner
│   ├── AppScanner
│   └── ApkFeatureExtractor
│
├── AI
│   ├── AiModel
│   ├── AiPrediction
│   ├── AiAnalysisState
│   └── ONNX Model
│
└── Security Analysis
├── Permission Analysis
├── Static Risk Score
└── AI Classification

App Analysis Flow

Select installed application
↓
Read application information
↓
Read requested permissions
↓
Calculate static risk
↓
Locate APK
↓
Extract DEX features
↓
Generate 50-feature vector
↓
Validate feature count
↓
Run ONNX model
↓
Display AI result
↓
Display final security verdict

Project Structure

app/
├── src/
│   └── main/
│       ├── java/com/example/mobilesecurity/
│       │   ├── ai/
│       │   ├── scanner/
│       │   └── ui/
│       ├── assets/
│       │   └── model.onnx
│       └── AndroidManifest.xml
│
├── build.gradle.kts
└── ...

Requirements

Android Studio

Android SDK

Kotlin

Android device or emulator

ONNX Runtime dependency

Running the Project

Clone the repository.

Open the project in Android Studio.

Allow Gradle to synchronize.

Connect an Android device or start an emulator.

Build and run the application.

Validation

The ONNX model was compared against the original scikit-learn Random
Forest model.

Sklearn shape: (15036, 2)
ONNX shape:    (15036, 2)

Maximum probability difference:
8.737429209038083e-07

Mean probability difference:
3.044119708094351e-07

Prediction agreement:
100.0000%

This confirms that the ONNX model produces effectively the same
predictions as the original scikit-learn model for the validation set.

Current Status

Installed application scanning

Permission analysis

Static risk scoring

APK/DEX feature extraction

50-feature validation

ONNX inference

AI confidence and probabilities

Individual application analysis

Rescan functionality

Active feature count

App details security UI

Important Notes

This is a small academic/project security scanner, not a replacement for
a full mobile antivirus or malware analysis platform.

The AI model is trained on a relatively small Drebin-based dataset.
Predictions should therefore be treated as an additional signal rather
than definitive proof that an application is malicious or safe.

Popular applications can legitimately contain many permissions and API
features that may also occur in malware datasets.

Disclaimer

This project is for educational and research purposes. Security
classifications are based on static indicators and a machine learning
model trained on a limited dataset and should not be considered
definitive malware detection.