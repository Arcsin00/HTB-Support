# Cat
Challenge Name: Cat
-------------------

*   **Status:** Active
*   **Category:** Mobile
*   **Difficulty:** Very Easy
*   **Date Owned:** 6/16/2023
*   Description:

> Easy leaks

<br>

File Review
-----------

The file provided is an android backup file. A bit of googling reveals a command we can use to unpack this file and inspect the contents.

```text-plain
( printf "\x1f\x8b\x08\x00\x00\x00\x00\x00" ; tail -c +25 cat.ab ) |  tar xfvz -
apps/com.android.basicsmsreceiver/_manifest
apps/com.android.bips/_manifest
apps/com.android.bluetoothmidiservice/_manifest
apps/com.android.bookmarkprovider/_manifest
apps/com.android.camera2/_manifest
apps/com.android.camera2/sp/com.android.camera2_preferences.xml
apps/com.android.captiveportallogin/_manifest
apps/com.android.carrierdefaultapp/_manifest
apps/com.android.contacts/_manifest
apps/com.android.contacts/sp/com.android.contacts.xml
apps/com.android.cts.ctsshim/_manifest
apps/com.android.cts.priv.ctsshim/_manifest
apps/com.android.dialer/_manifest
apps/com.android.dialer/sp/com.android.dialer_preferences.xml
apps/com.android.dreams.basic/_manifest
apps/com.android.egg/_manifest
apps/com.android.emergency/_manifest
apps/com.android.externalstorage/_manifest
apps/com.android.gallery3d/_manifest
apps/com.android.gallery3d/sp/com.android.gallery3d_preferences.xml
apps/com.android.htmlviewer/_manifest
apps/com.android.inputmethod.latin/_manifest
apps/com.android.inputmethod.latin/d_db/pendingUpdates.com.android.inputmethod.latin-shm
apps/com.android.inputmethod.latin/d_db/pendingUpdates.com.android.inputmethod.latin
apps/com.android.inputmethod.latin/d_db/pendingUpdates
apps/com.android.inputmethod.latin/d_db/pendingUpdates.com.android.inputmethod.latin-wal
apps/com.android.inputmethod.latin/d_db/pendingUpdates-wal
apps/com.android.inputmethod.latin/d_db/pendingUpdates-shm
apps/com.android.internal.display.cutout.emulation.corner/_manifest
apps/com.android.internal.display.cutout.emulation.double/_manifest
apps/com.android.internal.display.cutout.emulation.tall/_manifest
apps/com.android.launcher3/_manifest
apps/com.android.launcher3/sp/com.android.launcher3.prefs.xml
apps/com.android.managedprovisioning/_manifest
apps/com.android.mtp/_manifest
apps/com.android.mtp/db/database-wal
apps/com.android.mtp/db/database
apps/com.android.mtp/db/database-shm
apps/com.android.pacprocessor/_manifest
apps/com.android.providers.downloads.ui/_manifest
apps/com.android.providers.partnerbookmarks/_manifest
apps/com.android.providers.telephony/_manifest
apps/com.android.proxyhandler/_manifest
apps/com.android.settings.intelligence/_manifest
apps/com.android.settings.intelligence/sp/suggestions.xml
apps/com.android.settings.intelligence/sp/SuggestionEventStore.xml
apps/com.android.simappdialog/_manifest
apps/com.android.systemui.theme.dark/_manifest
apps/com.android.traceur/_manifest
apps/com.android.wallpaper.livepicker/_manifest
apps/com.android.wallpaperbackup/_manifest
apps/com.android.wallpaperbackup/f/empty
apps/com.android.wallpaperbackup/f/wallpaper-info-stage
apps/com.android.wallpapercropper/_manifest
apps/com.android.wallpaperpicker/_manifest
apps/com.example.android.notepad/_manifest
apps/com.example.android.rssreader/_manifest
apps/com.farmerbb.taskbar.androidx86/_manifest
apps/com.farmerbb.taskbar.androidx86/sp/com.farmerbb.taskbar.androidx86_preferences.xml
apps/com.google.android.backuptransport/_manifest
apps/com.google.android.ext.services/_manifest
apps/com.google.android.feedback/_manifest
apps/com.google.android.gms.setup/_manifest
apps/com.google.android.gsf.login/_manifest
apps/com.google.android.onetimeinitializer/_manifest
apps/com.google.android.onetimeinitializer/sp/oti.xml
apps/org.android_x86.analytics/_manifest
apps/org.android_x86.analytics/f/gaClientId
apps/org.android_x86.analytics/f/lastInfo.json
apps/org.android_x86.analytics/sp/org.android_x86.analytics.prefs.xml
apps/org.lineageos.eleven/_manifest
apps/org.lineageos.eleven/db/musicdb.db
apps/org.lineageos.eleven/db/musicdb.db-shm
apps/org.lineageos.eleven/db/musicdb.db-wal
shared/0/Alarms
shared/0/Download
shared/0/DCIM
shared/0/Pictures
shared/0/Pictures/IMAG0001.jpg
shared/0/Pictures/IMAG0006.jpg
shared/0/Pictures/IMAG0002.jpg
shared/0/Pictures/IMAG0003.jpg
shared/0/Pictures/IMAG0005.jpg
shared/0/Pictures/IMAG0004.jpg
gzip: shared/0/Podcasts
stdin: unexpected end of file
shared/0/Movies
shared/0/Notifications
shared/0/Music
shared/0/Ringtones
tar: Child returned status 1
tar: Error is not recoverable: exiting now
```

Those pictures look like some low hanging fruit that we can check quickly.

![](Cat/image.png)

Most of them are kittens, but the image of the guy with a censored face stands out so take a closer look at that one.

![](Cat/1_image.png)

Upon closer inspection of the document it appears to be a flag!

That was an easy one, congrats!