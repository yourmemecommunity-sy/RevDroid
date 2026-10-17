"""Small permission classification table.

Source: the protectionLevel values in the Android framework manifest
(frameworks/base/core/res/AndroidManifest.xml). "dangerous" = runtime
permissions the user must grant. "signature" = only granted to apps signed
with the platform key (or privileged system apps); a normal app asking for
them is a red flag. Anything not listed and in the android.permission
namespace is treated as "normal". Other namespaces are "custom".
"""
from __future__ import annotations

DANGEROUS: dict[str, str] = {
    # calendar
    "READ_CALENDAR": "Read calendar events", "WRITE_CALENDAR": "Add or modify calendar events",
    # camera / mic
    "CAMERA": "Take pictures and record video", "RECORD_AUDIO": "Record audio",
    # contacts
    "READ_CONTACTS": "Read contacts", "WRITE_CONTACTS": "Modify contacts", "GET_ACCOUNTS": "List accounts on the device",
    # location
    "ACCESS_FINE_LOCATION": "Precise location (GPS)", "ACCESS_COARSE_LOCATION": "Approximate location",
    "ACCESS_BACKGROUND_LOCATION": "Location while in the background", "ACCESS_MEDIA_LOCATION": "Location stored in photos",
    # phone
    "READ_PHONE_STATE": "Read phone status and identity", "READ_PHONE_NUMBERS": "Read phone numbers",
    "CALL_PHONE": "Place calls without user interaction", "ANSWER_PHONE_CALLS": "Answer incoming calls",
    "READ_CALL_LOG": "Read call history", "WRITE_CALL_LOG": "Modify call history",
    "ADD_VOICEMAIL": "Add voicemail", "USE_SIP": "Make SIP calls", "PROCESS_OUTGOING_CALLS": "Redirect outgoing calls",
    "ACCEPT_HANDOVER": "Continue a call started in another app",
    # sensors / activity
    "BODY_SENSORS": "Heart-rate and body sensors", "BODY_SENSORS_BACKGROUND": "Body sensors in background",
    "ACTIVITY_RECOGNITION": "Physical activity recognition",
    # sms
    "SEND_SMS": "Send SMS (may cost money)", "RECEIVE_SMS": "Receive SMS", "READ_SMS": "Read SMS messages",
    "RECEIVE_WAP_PUSH": "Receive WAP push", "RECEIVE_MMS": "Receive MMS",
    # storage / media
    "READ_EXTERNAL_STORAGE": "Read shared storage", "WRITE_EXTERNAL_STORAGE": "Write shared storage",
    "READ_MEDIA_IMAGES": "Read images", "READ_MEDIA_VIDEO": "Read videos", "READ_MEDIA_AUDIO": "Read audio files",
    "READ_MEDIA_VISUAL_USER_SELECTED": "Read user-selected media",
    # nearby devices / misc
    "BLUETOOTH_SCAN": "Discover Bluetooth devices", "BLUETOOTH_CONNECT": "Connect to paired Bluetooth devices",
    "BLUETOOTH_ADVERTISE": "Advertise to Bluetooth devices", "NEARBY_WIFI_DEVICES": "Discover nearby Wi-Fi devices",
    "UWB_RANGING": "Ultra-wideband ranging", "POST_NOTIFICATIONS": "Show notifications",
}

SIGNATURE: dict[str, str] = {
    "SYSTEM_ALERT_WINDOW": "Draw over other apps (overlay attacks)",
    "WRITE_SETTINGS": "Modify system settings",
    "REQUEST_INSTALL_PACKAGES": "Ask to install other APKs",
    "PACKAGE_USAGE_STATS": "See which apps are used",
    "BIND_ACCESSIBILITY_SERVICE": "Accessibility service (can read the screen)",
    "BIND_DEVICE_ADMIN": "Device administrator",
    "BIND_NOTIFICATION_LISTENER_SERVICE": "Read all notifications",
    "BIND_VPN_SERVICE": "Act as a VPN",
    "MANAGE_EXTERNAL_STORAGE": "All-files access",
    "INSTALL_PACKAGES": "Install apps silently (system only)",
    "DELETE_PACKAGES": "Uninstall apps (system only)",
    "READ_LOGS": "Read system logs (system only)",
    "WRITE_SECURE_SETTINGS": "Modify secure settings (system only)",
    "MOUNT_UNMOUNT_FILESYSTEMS": "Mount filesystems (system only)",
    "CHANGE_COMPONENT_ENABLED_STATE": "Enable/disable app components (system only)",
    "READ_PRIVILEGED_PHONE_STATE": "Read device identifiers (system only)",
    "MANAGE_ACCOUNTS": "Manage accounts", "BIND_INPUT_METHOD": "Act as a keyboard",
    "SCHEDULE_EXACT_ALARM": "Exact alarms", "QUERY_ALL_PACKAGES": "See every installed app",
}

NORMAL_HINTS: dict[str, str] = {
    "INTERNET": "Full network access", "ACCESS_NETWORK_STATE": "View network connections",
    "ACCESS_WIFI_STATE": "View Wi-Fi connections", "CHANGE_WIFI_STATE": "Change Wi-Fi state",
    "WAKE_LOCK": "Keep the device awake", "VIBRATE": "Control vibration",
    "RECEIVE_BOOT_COMPLETED": "Run at startup", "FOREGROUND_SERVICE": "Run foreground services",
    "BLUETOOTH": "Pair with Bluetooth devices", "NFC": "Use NFC", "USE_BIOMETRIC": "Use biometric hardware",
    "USE_FINGERPRINT": "Use fingerprint hardware", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": "Skip battery optimisation",
    "GET_TASKS": "List running apps (deprecated)", "KILL_BACKGROUND_PROCESSES": "Close other apps",
}

# Riskier subset used for the "sensitive permission" finding
HIGH_IMPACT = {"READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CALL_LOG", "PROCESS_OUTGOING_CALLS",
               "RECORD_AUDIO", "ACCESS_BACKGROUND_LOCATION", "READ_CONTACTS",
               "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "REQUEST_INSTALL_PACKAGES",
               "MANAGE_EXTERNAL_STORAGE", "QUERY_ALL_PACKAGES", "READ_LOGS", "INSTALL_PACKAGES"}


def classify(name: str) -> dict[str, str]:
    short = name.rsplit(".", 1)[-1]
    is_android = name.startswith("android.permission.")
    if is_android and short in DANGEROUS:
        level, desc = "dangerous", DANGEROUS[short]
    elif is_android and short in SIGNATURE:
        level, desc = "signature", SIGNATURE[short]
    elif is_android:
        level, desc = "normal", NORMAL_HINTS.get(short, "Standard Android permission")
    elif name.startswith("com.google.android.c2dm") or name.startswith("com.google.android.gms"):
        level, desc = "normal", "Google Play services permission"
    else:
        level, desc = "custom", "Custom or third-party permission"
    return {"name": name, "short_name": short, "protection_level": level, "description": desc,
            "high_impact": is_android and short in HIGH_IMPACT}
