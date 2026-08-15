package com.example.mobilesecurity.ui

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable

import androidx.compose.foundation.Image
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext

@Composable
fun AppIcon(
    packageName: String,
    modifier: Modifier = Modifier
) {

    val context = LocalContext.current

    val bitmap = remember(packageName) {

        try {

            val drawable =
                context.packageManager
                    .getApplicationIcon(packageName)

            drawableToBitmap(drawable)

        } catch (e: Exception) {

            null
        }
    }

    if (bitmap != null) {

        Image(
            bitmap = bitmap.asImageBitmap(),

            contentDescription =
                "App icon",

            modifier = modifier
        )

    } else {

        // If the icon cannot be loaded,
        // simply show nothing.
    }
}


private fun drawableToBitmap(
    drawable: Drawable
): Bitmap {

    val width =
        if (drawable.intrinsicWidth > 0)
            drawable.intrinsicWidth
        else
            96

    val height =
        if (drawable.intrinsicHeight > 0)
            drawable.intrinsicHeight
        else
            96

    val bitmap =
        Bitmap.createBitmap(
            width,
            height,
            Bitmap.Config.ARGB_8888
        )

    val canvas =
        Canvas(bitmap)

    drawable.setBounds(
        0,
        0,
        canvas.width,
        canvas.height
    )

    drawable.draw(canvas)

    return bitmap
}