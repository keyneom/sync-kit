package com.keyneom.synckit.stores

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri

/**
 * Opens a web Google Picker grant page in a full browser tab.
 *
 * Android cannot run the Picker, and a Storage Access Framework grant
 * authorizes nothing at the Drive API, so granting `drive.file` access to files
 * this application did not create means handing off to a web page that runs the
 * Picker. `drive.file` grants are keyed to the Cloud project rather than an
 * individual OAuth client, so a grant made in the browser is visible to this
 * application's Drive tokens. Afterwards, enumerate what was granted with
 * [listAccessibleSyncKitDatasets]; no return channel from the page is required.
 *
 * Three details decide whether the launch works, and each fails silently:
 *
 * 1. It must be a **full browser tab**, not a Custom Tab. Google Identity
 *    Services' popup token flow breaks inside a Custom Tab — the popup replaces
 *    the page and the token never reaches the opener.
 * 2. The browser package must be **resolved and forced**. An application that
 *    owns the App Link for its own web origin receives its own unaddressed
 *    `ACTION_VIEW` intents, so the grant page would open right back inside it.
 *    Resolution probes a neutral URL, because resolving the grant URL itself
 *    returns this application.
 * 3. There must be a **fallback**. This returns `false` when no browser can be
 *    resolved; offer the URL for the user to copy and open manually rather than
 *    failing silently.
 *
 * @return `true` when a browser was launched, `false` when none could be
 *   resolved and the caller should fall back to offering the link.
 */
fun launchGrantInBrowser(activity: Activity, url: String): Boolean {
    val probe = Intent(Intent.ACTION_VIEW, Uri.parse("https://www.google.com"))
        .addCategory(Intent.CATEGORY_BROWSABLE)
    val packageManager = activity.packageManager
    val browser = packageManager
        .resolveActivity(probe, PackageManager.MATCH_DEFAULT_ONLY)
        ?.activityInfo
        ?.packageName
        ?.takeIf { it.isUsableBrowser(activity) }
        ?: packageManager
            .queryIntentActivities(probe, 0)
            .asSequence()
            .map { it.activityInfo.packageName }
            .firstOrNull { it.isUsableBrowser(activity) }
        ?: return false
    activity.startActivity(
        Intent(Intent.ACTION_VIEW, Uri.parse(url))
            .addCategory(Intent.CATEGORY_BROWSABLE)
            .setPackage(browser),
    )
    return true
}

/**
 * Excludes this application (which may own the App Link for the grant origin)
 * and `android`, the system disambiguation activity, which is not a browser.
 */
private fun String.isUsableBrowser(activity: Activity): Boolean =
    this != activity.packageName && this != "android"
