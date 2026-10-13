package com.devicetrust.client

import android.app.Activity
import android.os.Build
import android.view.WindowManager

/**
 * Hardening for screens that show or confirm sensitive data (balances,
 * payee and amount, one-time codes):
 *
 * * `FLAG_SECURE` blocks screenshots, screen recording and casting of the window.
 * * On Android 12+, hides other apps' overlay windows while this window is
 *   visible, defeating tap-jacking and fake "helpdesk" overlays.
 *
 * Call from `onCreate` before `setContentView`.
 */
object SecureWindow {
    fun apply(activity: Activity) {
        activity.window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            activity.window.setHideOverlayWindows(true)
        }
    }
}
