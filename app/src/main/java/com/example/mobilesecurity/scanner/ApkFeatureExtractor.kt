package com.example.mobilesecurity.scanner

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.util.Log

import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.iface.Method
import org.jf.dexlib2.iface.instruction.ReferenceInstruction
import org.jf.dexlib2.iface.reference.MethodReference
import org.jf.dexlib2.iface.reference.StringReference
import org.jf.dexlib2.iface.reference.TypeReference

import java.io.File
import java.util.zip.ZipFile


class ApkFeatureExtractor(
    private val context: Context
) {

    companion object {

        /*
         * IMPORTANT:
         *
         * This order MUST remain exactly the same
         * as the order used when training the model.
         */

        val FEATURE_NAMES = listOf(

            "SEND_SMS",
            "READ_PHONE_STATE",
            "transact",
            "attachInterface",
            "android.os.Binder",
            "onServiceConnected",
            "ServiceConnection",
            "android.telephony.SmsManager",
            "bindService",
            "Ljava.lang.Class.getCanonicalName",
            "INTERNET",
            "TelephonyManager.getDeviceId",
            "Ljava.lang.Class.getMethods",
            "Ljava.lang.Class.cast",
            "TelephonyManager.getLine1Number",
            "RECEIVE_SMS",
            "Ljava.net.URLDecoder",
            "android.intent.action.BOOT_COMPLETED",
            "Landroid.content.Context.unregisterReceiver",
            "ClassLoader",
            "android.content.pm.Signature",
            "READ_SMS",
            "Landroid.content.Context.registerReceiver",
            "chmod",
            "TelephonyManager.getSubscriberId",
            "GET_ACCOUNTS",
            "Ljava.lang.Class.getResource",
            "android.telephony.gsm.SmsManager",
            "Ljava.lang.Class.getField",
            "Runtime.exec",
            "TelephonyManager.getNetworkOperator",
            "WRITE_HISTORY_BOOKMARKS",
            "Ljava.lang.Class.getMethod",
            "ACCESS_COARSE_LOCATION",
            "READ_HISTORY_BOOKMARKS",
            "Ljava.lang.Class.getDeclaredField",
            "ACCESS_WIFI_STATE",
            "HttpUriRequest",
            "getBinder",
            "WRITE_EXTERNAL_STORAGE",
            "android.content.pm.PackageInfo",
            "HttpGet.init",
            "HttpPost.init",
            "System.loadLibrary",
            "ACCESS_NETWORK_STATE",
            "/system/bin",
            "android.intent.action.SEND",
            "Ljava.lang.Object.getClass",
            "ACCESS_FINE_LOCATION",
            "Ljavax.crypto.spec.SecretKeySpec"
        )
    }


    // =========================================================
    // MAIN EXTRACTION
    // =========================================================

    fun extract(
        packageName: String
    ): FloatArray {

        val values =
            FloatArray(
                FEATURE_NAMES.size
            )


        // =====================================================
        // 1. PERMISSIONS
        // =====================================================

        extractPermissions(
            packageName,
            values
        )


        // =====================================================
        // 2. MANIFEST / INTENT FEATURES
        // =====================================================

        extractManifestFeatures(
            packageName,
            values
        )


        // =====================================================
        // 3. DEX FEATURES
        // =====================================================

        extractDexFeatures(
            packageName,
            values
        )


        // =====================================================
        // VALIDATION
        // =====================================================

        Log.d(
            "AI_VALIDATION",
            "================================"
        )

        Log.d(
            "AI_VALIDATION",
            "FEATURE COUNT = ${values.size}"
        )

        Log.d(
            "AI_VALIDATION",
            "EXPECTED COUNT = ${FEATURE_NAMES.size}"
        )

        for (i in FEATURE_NAMES.indices) {

            Log.d(
                "AI_VALIDATION",
                "$i | ${FEATURE_NAMES[i]} | ${values[i]}"
            )
        }

        Log.d(
            "AI_VALIDATION",
            "================================"
        )


        return values
    }


    // =========================================================
    // PERMISSIONS
    // =========================================================

    private fun extractPermissions(
        packageName: String,
        values: FloatArray
    ) {

        try {

            @Suppress("DEPRECATION")
            val packageInfo =
                context.packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_PERMISSIONS
                )


            val permissions =
                packageInfo.requestedPermissions
                    ?.toSet()
                    ?: emptySet()


            setPermission(
                values,
                "SEND_SMS",
                "android.permission.SEND_SMS",
                permissions
            )

            setPermission(
                values,
                "READ_PHONE_STATE",
                "android.permission.READ_PHONE_STATE",
                permissions
            )

            setPermission(
                values,
                "INTERNET",
                "android.permission.INTERNET",
                permissions
            )

            setPermission(
                values,
                "RECEIVE_SMS",
                "android.permission.RECEIVE_SMS",
                permissions
            )

            setPermission(
                values,
                "READ_SMS",
                "android.permission.READ_SMS",
                permissions
            )

            setPermission(
                values,
                "GET_ACCOUNTS",
                "android.permission.GET_ACCOUNTS",
                permissions
            )

            setPermission(
                values,
                "ACCESS_COARSE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                permissions
            )

            setPermission(
                values,
                "READ_HISTORY_BOOKMARKS",
                "android.permission.READ_HISTORY_BOOKMARKS",
                permissions
            )

            setPermission(
                values,
                "WRITE_HISTORY_BOOKMARKS",
                "android.permission.WRITE_HISTORY_BOOKMARKS",
                permissions
            )

            setPermission(
                values,
                "ACCESS_WIFI_STATE",
                "android.permission.ACCESS_WIFI_STATE",
                permissions
            )

            setPermission(
                values,
                "WRITE_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                permissions
            )

            setPermission(
                values,
                "ACCESS_NETWORK_STATE",
                "android.permission.ACCESS_NETWORK_STATE",
                permissions
            )

            setPermission(
                values,
                "ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_FINE_LOCATION",
                permissions
            )

        } catch (e: Exception) {

            Log.e(
                "AI_EXTRACTOR",
                "Permission extraction failed for $packageName",
                e
            )
        }
    }


    private fun setPermission(
        values: FloatArray,
        featureName: String,
        permission: String,
        permissions: Set<String>
    ) {

        val index =
            FEATURE_NAMES.indexOf(
                featureName
            )

        if (index < 0) {
            return
        }

        values[index] =
            if (permission in permissions) {
                1f
            } else {
                0f
            }
    }


    // =========================================================
    // MANIFEST / INTENT FEATURES
    // =========================================================

    private fun extractManifestFeatures(
        packageName: String,
        values: FloatArray
    ) {

        val pm =
            context.packageManager

        try {

            // =================================================
            // BOOT_COMPLETED
            // =================================================

            val bootIntent =
                Intent(
                    "android.intent.action.BOOT_COMPLETED"
                ).apply {

                    setPackage(
                        packageName
                    )
                }


            val bootReceivers =
                pm.queryBroadcastReceivers(
                    bootIntent,
                    PackageManager.MATCH_ALL
                )


            if (
                bootReceivers.isNotEmpty()
            ) {

                setFeature(
                    values,
                    "android.intent.action.BOOT_COMPLETED"
                )
            }


            // =================================================
            // SEND
            // =================================================

            val sendIntent =
                Intent(
                    "android.intent.action.SEND"
                ).apply {

                    type = "*/*"

                    setPackage(
                        packageName
                    )
                }


            val sendActivities =
                pm.queryIntentActivities(
                    sendIntent,
                    PackageManager.MATCH_ALL
                )


            if (
                sendActivities.isNotEmpty()
            ) {

                setFeature(
                    values,
                    "android.intent.action.SEND"
                )
            }

        } catch (e: Exception) {

            Log.e(
                "AI_EXTRACTOR",
                "Manifest extraction failed for $packageName",
                e
            )
        }
    }


    // =========================================================
    // DEX EXTRACTION
    // =========================================================

    private fun extractDexFeatures(
        packageName: String,
        values: FloatArray
    ) {

        try {

            val applicationInfo =
                context.packageManager
                    .getApplicationInfo(
                        packageName,
                        0
                    )


            val apkPath =
                applicationInfo.sourceDir


            Log.d(
                "AI_EXTRACTOR",
                "APK = $apkPath"
            )


            ZipFile(
                apkPath
            ).use { zip ->


                val dexEntries =
                    zip.entries()
                        .asSequence()
                        .filter {

                            it.name.endsWith(
                                ".dex",
                                ignoreCase = true
                            )

                        }
                        .toList()


                Log.d(
                    "AI_EXTRACTOR",
                    "DEX files found = ${dexEntries.size}"
                )


                for (
                entry in dexEntries
                ) {

                    Log.d(
                        "AI_EXTRACTOR",
                        "Parsing ${entry.name}"
                    )


                    val tempDex =
                        File.createTempFile(
                            "security_scan_",
                            ".dex",
                            context.cacheDir
                        )


                    try {

                        zip.getInputStream(
                            entry
                        ).use { input ->

                            tempDex.outputStream()
                                .use { output ->

                                    input.copyTo(
                                        output
                                    )
                                }
                        }


                        analyzeDexFile(
                            tempDex,
                            values
                        )

                    } finally {

                        tempDex.delete()
                    }
                }
            }

        } catch (e: Exception) {

            Log.e(
                "AI_EXTRACTOR",
                "DEX extraction failed for $packageName",
                e
            )
        }
    }


    // =========================================================
    // DEXLIB2
    // =========================================================

    private fun analyzeDexFile(
        dexFile: File,
        values: FloatArray
    ) {

        try {

            val dex =
                DexFileFactory.loadDexFile(
                    dexFile,
                    null
                )


            Log.d(
                "AI_EXTRACTOR",
                "Classes = ${dex.classes.size}"
            )


            for (
            classDef in dex.classes
            ) {

                // ---------------------------------------------
                // Class references
                // ---------------------------------------------

                detectClass(
                    classDef.type,
                    values
                )


                // ---------------------------------------------
                // Methods defined in the class
                // ---------------------------------------------

                for (
                method in classDef.methods
                ) {

                    detectDefinedMethod(
                        method,
                        values
                    )


                    // -----------------------------------------
                    // IMPORTANT:
                    //
                    // Inspect instructions.
                    //
                    // This catches references to Android
                    // framework APIs called by the APK.
                    // -----------------------------------------

                    inspectMethodInstructions(
                        method,
                        values
                    )
                }
            }

        } catch (e: Exception) {

            Log.e(
                "AI_EXTRACTOR",
                "Failed to parse ${dexFile.name}",
                e
            )
        }
    }


    // =========================================================
    // CLASS DETECTION
    // =========================================================

    private fun detectClass(
        className: String,
        values: FloatArray
    ) {

        when (className) {

            "Landroid/os/Binder;" -> {

                setFeature(
                    values,
                    "android.os.Binder"
                )
            }


            "Landroid/content/ServiceConnection;" -> {

                setFeature(
                    values,
                    "ServiceConnection"
                )
            }


            "Ljava/lang/ClassLoader;" -> {

                setFeature(
                    values,
                    "ClassLoader"
                )
            }


            "Landroid/content/pm/Signature;" -> {

                setFeature(
                    values,
                    "android.content.pm.Signature"
                )
            }


            "Landroid/content/pm/PackageInfo;" -> {

                setFeature(
                    values,
                    "android.content.pm.PackageInfo"
                )
            }


            "Ljava/net/URLDecoder;" -> {

                setFeature(
                    values,
                    "Ljava.net.URLDecoder"
                )
            }


            "Ljavax/crypto/spec/SecretKeySpec;" -> {

                setFeature(
                    values,
                    "Ljavax.crypto.spec.SecretKeySpec"
                )
            }
        }
    }


    // =========================================================
    // METHODS DEFINED BY THE APK
    // =========================================================

    private fun detectDefinedMethod(
        method: Method,
        values: FloatArray
    ) {

        val name =
            method.name

        val definingClass =
            method.definingClass


        // -----------------------------------------------------
        // getBinder
        // -----------------------------------------------------

        if (
            name == "getBinder"
        ) {

            setFeature(
                values,
                "getBinder"
            )
        }


        // -----------------------------------------------------
        // Context methods
        // -----------------------------------------------------

        if (
            definingClass ==
            "Landroid/content/Context;"
        ) {

            when (name) {

                "bindService" -> {

                    setFeature(
                        values,
                        "bindService"
                    )
                }

                "registerReceiver" -> {

                    setFeature(
                        values,
                        "Landroid.content.Context.registerReceiver"
                    )
                }

                "unregisterReceiver" -> {

                    setFeature(
                        values,
                        "Landroid.content.Context.unregisterReceiver"
                    )
                }
            }
        }
    }


    // =========================================================
    // INSTRUCTION / API REFERENCE ANALYSIS
    // =========================================================

    private fun inspectMethodInstructions(
        method: Method,
        values: FloatArray
    ) {

        val implementation =
            method.implementation
                ?: return


        for (
        instruction in implementation.instructions
        ) {

            if (
                instruction !is ReferenceInstruction
            ) {
                continue
            }


            val reference =
                instruction.reference


            // =================================================
            // METHOD REFERENCES
            // =================================================

            if (
                reference is MethodReference
            ) {

                inspectMethodReference(
                    reference,
                    values
                )
            }


            // =================================================
            // STRING REFERENCES
            // =================================================

            if (
                reference is StringReference
            ) {

                inspectStringReference(
                    reference.string,
                    values
                )
            }


            // =================================================
            // TYPE REFERENCES
            // =================================================

            if (
                reference is TypeReference
            ) {

                inspectTypeReference(
                    reference.type,
                    values
                )
            }
        }
    }


    // =========================================================
    // METHOD REFERENCES
    // =========================================================

    private fun inspectMethodReference(
        reference: MethodReference,
        values: FloatArray
    ) {

        val methodName =
            reference.name

        val owner =
            reference.definingClass


        // =====================================================
        // BINDER
        // =====================================================

        if (
            methodName == "transact"
        ) {

            setFeature(
                values,
                "transact"
            )
        }


        if (
            methodName == "attachInterface"
        ) {

            setFeature(
                values,
                "attachInterface"
            )
        }


        // =====================================================
        // SERVICE
        // =====================================================

        if (
            methodName == "onServiceConnected"
        ) {

            setFeature(
                values,
                "onServiceConnected"
            )
        }


        if (
            methodName == "bindService"
        ) {

            setFeature(
                values,
                "bindService"
            )
        }


        // =====================================================
        // JAVA CLASS REFLECTION
        // =====================================================

        if (
            owner ==
            "Ljava/lang/Class;"
        ) {

            when (methodName) {

                "getCanonicalName" -> {

                    setFeature(
                        values,
                        "Ljava.lang.Class.getCanonicalName"
                    )
                }


                "getMethods" -> {

                    setFeature(
                        values,
                        "Ljava.lang.Class.getMethods"
                    )
                }


                "cast" -> {

                    setFeature(
                        values,
                        "Ljava.lang.Class.cast"
                    )
                }


                "getResource" -> {

                    setFeature(
                        values,
                        "Ljava.lang.Class.getResource"
                    )
                }


                "getField" -> {

                    setFeature(
                        values,
                        "Ljava.lang.Class.getField"
                    )
                }


                "getMethod" -> {

                    setFeature(
                        values,
                        "Ljava.lang.Class.getMethod"
                    )
                }
            }
        }


        // =====================================================
        // TELEPHONY
        // =====================================================

        if (
            owner ==
            "Landroid/telephony/TelephonyManager;"
        ) {

            when (methodName) {

                "getDeviceId" -> {

                    setFeature(
                        values,
                        "TelephonyManager.getDeviceId"
                    )
                }


                "getLine1Number" -> {

                    setFeature(
                        values,
                        "TelephonyManager.getLine1Number"
                    )
                }


                "getSubscriberId" -> {

                    setFeature(
                        values,
                        "TelephonyManager.getSubscriberId"
                    )
                }


                "getNetworkOperator" -> {

                    setFeature(
                        values,
                        "TelephonyManager.getNetworkOperator"
                    )
                }
            }
        }


        // =====================================================
        // SMS MANAGER
        // =====================================================

        if (
            owner ==
            "Landroid/telephony/SmsManager;"
        ) {

            setFeature(
                values,
                "android.telephony.SmsManager"
            )
        }


        if (
            owner ==
            "Landroid/telephony/gsm/SmsManager;"
        ) {

            setFeature(
                values,
                "android.telephony.gsm.SmsManager"
            )
        }


        // =====================================================
        // RUNTIME.EXEC
        // =====================================================

        if (
            owner ==
            "Ljava/lang/Runtime;" &&
            methodName == "exec"
        ) {

            setFeature(
                values,
                "Runtime.exec"
            )
        }


        // =====================================================
        // SYSTEM.LOADLIBRARY
        // =====================================================

        if (
            owner ==
            "Ljava/lang/System;" &&
            methodName == "loadLibrary"
        ) {

            setFeature(
                values,
                "System.loadLibrary"
            )
        }


        // =====================================================
        // OBJECT.GETCLASS
        // =====================================================

        if (
            owner ==
            "Ljava/lang/Object;" &&
            methodName == "getClass"
        ) {

            setFeature(
                values,
                "Ljava.lang.Object.getClass"
            )
        }


        // =====================================================
        // CONTEXT
        // =====================================================

        if (
            owner ==
            "Landroid/content/Context;"
        ) {

            when (methodName) {

                "registerReceiver" -> {

                    setFeature(
                        values,
                        "Landroid.content.Context.registerReceiver"
                    )
                }


                "unregisterReceiver" -> {

                    setFeature(
                        values,
                        "Landroid.content.Context.unregisterReceiver"
                    )
                }


                "bindService" -> {

                    setFeature(
                        values,
                        "bindService"
                    )
                }
            }
        }


        // =====================================================
        // GENERIC getBinder
        // =====================================================

        if (
            methodName == "getBinder"
        ) {

            setFeature(
                values,
                "getBinder"
            )
        }


        // =====================================================
        // HTTP
        // =====================================================

        if (
            owner.contains(
                "HttpUriRequest"
            )
        ) {

            setFeature(
                values,
                "HttpUriRequest"
            )
        }


        if (
            owner.contains(
                "HttpGet"
            ) &&
            methodName == "<init>"
        ) {

            setFeature(
                values,
                "HttpGet.init"
            )
        }


        if (
            owner.contains(
                "HttpPost"
            ) &&
            methodName == "<init>"
        ) {

            setFeature(
                values,
                "HttpPost.init"
            )
        }


        // =====================================================
        // URL DECODER
        // =====================================================

        if (
            owner ==
            "Ljava/net/URLDecoder;"
        ) {

            setFeature(
                values,
                "Ljava.net.URLDecoder"
            )
        }


        // =====================================================
        // SIGNATURE
        // =====================================================

        if (
            owner ==
            "Landroid/content/pm/Signature;"
        ) {

            setFeature(
                values,
                "android.content.pm.Signature"
            )
        }


        // =====================================================
        // PACKAGE INFO
        // =====================================================

        if (
            owner ==
            "Landroid/content/pm/PackageInfo;"
        ) {

            setFeature(
                values,
                "android.content.pm.PackageInfo"
            )
        }


        // =====================================================
        // SECRET KEY SPEC
        // =====================================================

        if (
            owner ==
            "Ljavax/crypto/spec/SecretKeySpec;"
        ) {

            setFeature(
                values,
                "Ljavax.crypto.spec.SecretKeySpec"
            )
        }
    }


    // =========================================================
    // STRING REFERENCES
    // =========================================================

    private fun inspectStringReference(
        value: String,
        values: FloatArray
    ) {

        // -----------------------------------------------------
        // chmod
        // -----------------------------------------------------

        if (
            value == "chmod"
        ) {

            setFeature(
                values,
                "chmod"
            )
        }


        // -----------------------------------------------------
        // /system/bin
        // -----------------------------------------------------

        if (
            value.contains(
                "/system/bin"
            )
        ) {

            setFeature(
                values,
                "/system/bin"
            )
        }


        // -----------------------------------------------------
        // BOOT_COMPLETED
        // -----------------------------------------------------

        if (
            value ==
            "android.intent.action.BOOT_COMPLETED"
        ) {

            setFeature(
                values,
                "android.intent.action.BOOT_COMPLETED"
            )
        }


        // -----------------------------------------------------
        // SEND
        // -----------------------------------------------------

        if (
            value ==
            "android.intent.action.SEND"
        ) {

            setFeature(
                values,
                "android.intent.action.SEND"
            )
        }
    }


    // =========================================================
    // TYPE REFERENCES
    // =========================================================

    private fun inspectTypeReference(
        type: String,
        values: FloatArray
    ) {

        when (type) {

            "Landroid/os/Binder;" -> {

                setFeature(
                    values,
                    "android.os.Binder"
                )
            }


            "Landroid/content/ServiceConnection;" -> {

                setFeature(
                    values,
                    "ServiceConnection"
                )
            }


            "Ljava/lang/ClassLoader;" -> {

                setFeature(
                    values,
                    "ClassLoader"
                )
            }


            "Landroid/content/pm/Signature;" -> {

                setFeature(
                    values,
                    "android.content.pm.Signature"
                )
            }


            "Landroid/content/pm/PackageInfo;" -> {

                setFeature(
                    values,
                    "android.content.pm.PackageInfo"
                )
            }


            "Ljava/net/URLDecoder;" -> {

                setFeature(
                    values,
                    "Ljava.net.URLDecoder"
                )
            }


            "Ljavax/crypto/spec/SecretKeySpec;" -> {

                setFeature(
                    values,
                    "Ljavax.crypto.spec.SecretKeySpec"
                )
            }
        }


        // -----------------------------------------------------
        // HTTP interfaces/classes
        // -----------------------------------------------------

        if (
            type.contains(
                "HttpUriRequest"
            )
        ) {

            setFeature(
                values,
                "HttpUriRequest"
            )
        }
    }


    // =========================================================
    // SET FEATURE
    // =========================================================

    private fun setFeature(
        values: FloatArray,
        featureName: String
    ) {

        val index =
            FEATURE_NAMES.indexOf(
                featureName
            )


        if (
            index >= 0
        ) {

            values[index] = 1f
        }
    }
}