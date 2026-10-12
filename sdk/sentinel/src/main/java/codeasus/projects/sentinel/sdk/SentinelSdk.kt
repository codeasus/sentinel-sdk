package codeasus.projects.sentinel.sdk

import android.Manifest
import android.content.Context
import androidx.annotation.RequiresPermission


@RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
fun check(ctx: Context) {

    val tamperReport = TamperDetector.evaluate(ctx)
    val networkInterceptionReport = NetworkDetector.evaluate(ctx)
}