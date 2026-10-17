"""Static code rules.

Each rule is a regex plus metadata. `secret=True` means group 1 holds a
credential: it is masked before it is stored anywhere. `hint` is a cheap
lower-case substring test run on the whole file before the regex, which keeps
scanning fast. `multiline=True` rules run on the whole file instead of per line.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str      # secrets | crypto | network | webview | logging | storage | injection
    severity: str
    pattern: str
    description: str
    recommendation: str
    hint: tuple[str, ...] = ()
    secret: bool = False
    placeholder_check: bool = False  # True for loose "name = value" rules that also match UI text
    multiline: bool = False
    cwe: str | None = None
    masvs: str | None = None
    exts: tuple[str, ...] = (".java", ".kt", ".xml", ".json", ".properties")
    regex: re.Pattern = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        flags = re.DOTALL if self.multiline else 0
        object.__setattr__(self, "regex", re.compile(self.pattern, flags))


# Values that look like a secret assignment but are placeholders or UI text.
PLACEHOLDERS = re.compile(
    r"^(?:password|passwd|secret|token|changeme|example|test|null|none|true|false|xxx+|\*+|your[_ ]?\w*|"
    r"enter\w*|<[^>]*>|\$\{[^}]*\}|%[sd]|.*\s.*)$", re.I)

RULES: list[Rule] = [
    # ------------------------------------------------------------- secrets
    Rule("SEC-PRIVATE-KEY", "Hardcoded private key", "secrets", "critical",
         # capture the header *and* the rest of the literal so the key body is masked too
         r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[^\"<]*)",
         "A private key shipped inside the APK can be extracted by anyone who downloads the app.",
         "Never bundle private keys. Keep them on the server, or generate per-device keys in the Android Keystore.",
         hint=("private key",), secret=True, cwe="CWE-321", masvs="MASVS-CRYPTO-2"),
    Rule("SEC-AWS-ACCESS-KEY", "AWS access key ID", "secrets", "critical",
         r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b",
         "AWS access key IDs pair with a secret key to give direct access to cloud resources.",
         "Revoke the key in IAM now. Use Cognito or a backend that issues short-lived, least-privilege credentials.",
         hint=("akia", "asia"), secret=True, cwe="CWE-798", masvs="MASVS-AUTH-1"),
    Rule("SEC-AWS-SECRET", "AWS secret access key", "secrets", "critical",
         r"(?i)aws.{0,30}?['\"]([A-Za-z0-9/+=]{40})['\"]",
         "An AWS secret access key gives full API access with the permissions of its IAM user.",
         "Revoke and rotate the key; never embed long-lived AWS credentials in a client app.",
         hint=("aws",), secret=True, cwe="CWE-798", masvs="MASVS-AUTH-1"),
    Rule("SEC-GOOGLE-API-KEY", "Google API key", "secrets", "medium",
         r"\b(AIza[0-9A-Za-z_\-]{35})\b",
         "Google API keys in apps are often expected (Firebase, Maps), but an unrestricted key can be abused "
         "and billed to you.",
         "In Google Cloud Console restrict the key to your package name + signing SHA-1 and to the APIs you use.",
         hint=("aiza",), secret=True, cwe="CWE-798", masvs="MASVS-AUTH-1"),
    Rule("SEC-STRIPE-KEY", "Stripe live secret key", "secrets", "critical",
         r"\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})\b",
         "A live Stripe secret key can create charges and refunds and read customer data.",
         "Roll the key in the Stripe dashboard; only publishable keys (pk_live_) belong in apps.",
         hint=("_live_",), secret=True, cwe="CWE-798", masvs="MASVS-AUTH-1"),
    Rule("SEC-GITHUB-TOKEN", "GitHub token", "secrets", "critical",
         r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b",
         "GitHub tokens give access to repositories and organisation data.",
         "Revoke the token on GitHub and move the call to a backend.",
         hint=("ghp_", "gho_", "ghu_", "ghs_", "ghr_"), secret=True, cwe="CWE-798"),
    Rule("SEC-SLACK-TOKEN", "Slack token", "secrets", "high",
         r"\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b",
         "Slack tokens can read and post messages in a workspace.",
         "Revoke the token in Slack and proxy the integration through your backend.",
         hint=("xox",), secret=True, cwe="CWE-798"),
    Rule("SEC-JWT", "Hardcoded JSON Web Token", "secrets", "high",
         r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b",
         "A hardcoded JWT is a bearer credential; anyone holding it can call the API as that identity.",
         "Obtain tokens at runtime after authentication, store them in EncryptedSharedPreferences, and expire them.",
         hint=("eyj",), secret=True, cwe="CWE-798", masvs="MASVS-AUTH-1"),
    Rule("SEC-PASSWORD", "Hardcoded password", "secrets", "high",
         r"(?i)\b\w*(?:password|passwd|pwd)\w*\s*=\s*\"([^\"]{4,})\"",
         "Passwords in code are the same for every install and are trivially recovered by decompiling.",
         "Remove the credential. Ask the user for it, or authenticate against a backend that issues tokens.",
         hint=("pass", "pwd"), secret=True, placeholder_check=True, cwe="CWE-259", masvs="MASVS-AUTH-1"),
    Rule("SEC-GENERIC-KEY", "Hardcoded API key, secret or token", "secrets", "high",
         r"(?i)\b\w*(?:api_?key|apikey|secret|access_?token|auth_?token|client_?secret|private_?key)\w*"
         r"\s*=\s*\"([A-Za-z0-9_\-+/=.]{12,})\"",
         "A credential string assigned in code ships to every user of the app.",
         "Move secrets to a backend; if a key must ship, restrict it server-side and treat it as public.",
         hint=("key", "secret", "token"), secret=True, placeholder_check=True, cwe="CWE-798", masvs="MASVS-AUTH-1"),
    Rule("SEC-XML-SECRET", "Credential in a string resource", "secrets", "high",
         r"(?i)<string name=\"[^\"]*(?:password|secret|api_?key|token|client_id)[^\"]*\">([^<\s]{8,})</string>",
         "Values in res/values/strings.xml are stored in plain text inside the APK.",
         "Remove the value from resources; fetch it from a backend or restrict it server-side.",
         hint=("<string",), secret=True, placeholder_check=True, cwe="CWE-798", masvs="MASVS-STORAGE-1", exts=(".xml",)),
    Rule("SEC-FIREBASE-URL", "Firebase Realtime Database URL", "secrets", "medium",
         r"(https?://[a-z0-9.-]+\.(?:firebaseio\.com|firebasedatabase\.app))",
         "Misconfigured Firebase databases are often readable by anyone. Check that /.json returns "
         "\"Permission denied\".",
         "Enforce authentication in Firebase Security Rules; never use \".read\": true in production.",
         hint=("firebaseio", "firebasedatabase"), cwe="CWE-284", masvs="MASVS-STORAGE-1"),

    # -------------------------------------------------------------- crypto
    Rule("CRY-WEAK-HASH", "Weak hash algorithm (MD5/SHA-1)", "crypto", "medium",
         r"MessageDigest\.getInstance\(\s*\"(MD5|MD4|MD2|SHA-?1)\"",
         "MD5 and SHA-1 are broken for collision resistance and too fast for password hashing.",
         "Use SHA-256+ for integrity, and PBKDF2/bcrypt/Argon2 for passwords.",
         hint=("messagedigest",), cwe="CWE-328", masvs="MASVS-CRYPTO-1"),
    Rule("CRY-ECB", "Block cipher in ECB mode", "crypto", "high",
         r"Cipher\.getInstance\(\s*\"(?:[A-Za-z0-9]+/ECB/[^\"]*|AES|DES|DESede)\"\s*\)",
         "ECB encrypts identical blocks to identical output and leaks patterns. Cipher.getInstance(\"AES\") "
         "silently defaults to AES/ECB/PKCS5Padding.",
         "Use AES/GCM/NoPadding with a random 12-byte IV per message.",
         hint=("cipher.getinstance",), cwe="CWE-327", masvs="MASVS-CRYPTO-1"),
    Rule("CRY-WEAK-CIPHER", "Obsolete cipher (DES/3DES/RC4/Blowfish)", "crypto", "medium",
         r"Cipher\.getInstance\(\s*\"((?:DES|DESede|TripleDES|RC4|ARCFOUR|RC2|Blowfish)(?:/[^\"]*)?)\"",
         "These ciphers have short keys or known practical attacks.",
         "Use AES-256-GCM or ChaCha20-Poly1305.",
         hint=("cipher.getinstance",), cwe="CWE-327", masvs="MASVS-CRYPTO-1"),
    Rule("CRY-HARDCODED-KEY", "Hardcoded encryption key", "crypto", "high",
         r"new SecretKeySpec\(\s*\"([^\"]+)\"\.getBytes",
         "An encryption key in the code is the same for every user, so the encryption only hides data from "
         "people who have not decompiled the app.",
         "Generate keys in the Android Keystore (KeyGenParameterSpec) and never export them.",
         hint=("secretkeyspec",), secret=True, placeholder_check=True, cwe="CWE-321", masvs="MASVS-CRYPTO-2"),
    Rule("CRY-STATIC-IV", "Static initialisation vector", "crypto", "medium",
         r"new IvParameterSpec\(\s*(?:new byte\[\]\s*\{|\"[^\"]*\"\.getBytes)",
         "Reusing a fixed IV makes CBC deterministic and completely breaks GCM.",
         "Generate a fresh random IV with SecureRandom for every encryption and store it with the ciphertext.",
         hint=("ivparameterspec",), cwe="CWE-329", masvs="MASVS-CRYPTO-1"),

    # ----------------------------------------------------- network / TLS
    Rule("NET-TRUST-ALL", "TrustManager accepts every certificate", "network", "critical",
         r"void checkServerTrusted\([^)]*\)\s*(?:throws [\w.,\s]+)?\{\s*\}",
         "An empty checkServerTrusted disables TLS certificate validation, so any man-in-the-middle can read "
         "and change the traffic.",
         "Delete the custom TrustManager and use the platform default; use certificate pinning via "
         "network security config if needed.",
         hint=("checkservertrusted",), multiline=True, cwe="CWE-295", masvs="MASVS-NETWORK-1", exts=(".java", ".kt")),
    Rule("NET-HOSTNAME-ALL", "Hostname verification disabled", "network", "high",
         r"(ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|NoopHostnameVerifier|"
         r"boolean verify\(String \w+, SSLSession \w+\)\s*\{\s*return true;\s*\})",
         "Accepting any hostname lets an attacker present a valid certificate for a different domain.",
         "Use the default HostnameVerifier (HttpsURLConnection.getDefaultHostnameVerifier()).",
         hint=("hostnameverifier", "sslsession"), multiline=True, cwe="CWE-297", masvs="MASVS-NETWORK-1",
         exts=(".java", ".kt")),
    Rule("NET-SSL-ERROR-PROCEED", "WebView ignores SSL errors", "network", "high",
         r"onReceivedSslError\([^)]*\)\s*\{[^}]{0,300}?\.proceed\(\)",
         "Calling handler.proceed() loads the page even when its certificate is invalid.",
         "Call handler.cancel() (the default) and fix the server certificate instead.",
         hint=("onreceivedsslerror",), multiline=True, cwe="CWE-295", masvs="MASVS-NETWORK-1",
         exts=(".java", ".kt")),
    Rule("NET-HTTP-URL", "Plain HTTP URL", "network", "low",
         r"\"(http://(?!localhost|127\.0\.0\.1|10\.0\.2\.2|schemas\.android\.com|www\.w3\.org|xml\.org|"
         r"ns\.adobe\.com|(?:www\.)?apache\.org|schemas\.xmlsoap\.org|purl\.org|xmlpull\.org|"
         r"java\.sun\.com|xmlns\.jcp\.org|schemas\.microsoft\.com)[^\s\"']{4,})\"",
         "Requests over HTTP are unencrypted and can be read or modified on the network.",
         "Switch the endpoint to HTTPS.",
         hint=("http://",), cwe="CWE-319", masvs="MASVS-NETWORK-1", exts=(".java", ".kt", ".xml", ".json")),

    # ------------------------------------------------------------ webview
    Rule("WEB-FILE-ACCESS", "WebView file access from URLs enabled", "webview", "medium",
         r"(setAllowUniversalAccessFromFileURLs\(true\)|setAllowFileAccessFromFileURLs\(true\))",
         "Lets JavaScript in a file:// page read other local files, including the app's private data.",
         "Leave these settings false; load local content through WebViewAssetLoader instead.",
         hint=("fromfileurls",), cwe="CWE-200", masvs="MASVS-PLATFORM-2", exts=(".java", ".kt")),

    # ------------------------------------------------------------ logging
    Rule("LOG-SENSITIVE", "Sensitive data written to the log", "logging", "medium",
         r"\bLog\.[vdiwe]\([^;]*(?i:password|passwd|token|secret|credit.?card|card.?number|cvv|ssn|otp|pin\b|"
         r"session|cookie|auth)",
         "Logcat output is readable over adb, in bug reports and, on old Android versions, by other apps.",
         "Remove sensitive values from logs and strip Log calls from release builds with R8 rules.",
         hint=("log.",), cwe="CWE-532", masvs="MASVS-STORAGE-2", exts=(".java", ".kt")),

    # ------------------------------------------------------ storage / sql
    Rule("STO-WORLD-READABLE", "World-readable or writeable file mode", "storage", "high",
         # jadx inlines the constants, so also match the numeric modes 1 (READABLE), 2 (WRITEABLE), 3 (both)
         r"(\bMODE_WORLD_(?:READABLE|WRITEABLE)\b|"
         r"\b(?:getSharedPreferences|openFileOutput|getDir|openOrCreateDatabase)\(\s*[^,()]+,\s*[123]\s*[,)])",
         "Files created with these modes can be read or modified by every app on the device.",
         "Use MODE_PRIVATE and share data through a FileProvider when needed.",
         hint=("mode_world", "getsharedpreferences", "openfileoutput", "getdir", "openorcreatedatabase"), cwe="CWE-276", masvs="MASVS-STORAGE-1", exts=(".java", ".kt")),
    Rule("STO-EXTERNAL", "Data written to shared external storage", "storage", "low",
         r"\b(getExternalStorageDirectory|getExternalStoragePublicDirectory)\(",
         "Shared storage can be read by other apps with storage permissions.",
         "Keep sensitive files in getFilesDir(); use scoped storage for user media.",
         hint=("getexternalstorage",), cwe="CWE-922", masvs="MASVS-STORAGE-1", exts=(".java", ".kt")),
    Rule("INJ-SQL-CONCAT", "SQL query built by string concatenation", "injection", "medium",
         r"\.(?:rawQuery|execSQL)\(\s*\"[^\"]*\"\s*\+",
         "Concatenating input into SQL allows SQL injection, especially through exported content providers.",
         "Use parameterised queries: rawQuery(\"... WHERE id = ?\", new String[]{id}).",
         hint=("rawquery", "execsql"), cwe="CWE-89", masvs="MASVS-CODE-4", exts=(".java", ".kt")),
]

# Special pairwise rule handled in the scanner: JS enabled + JS bridge in the same file.
WEBVIEW_JS = re.compile(r"setJavaScriptEnabled\(true\)")
WEBVIEW_BRIDGE = re.compile(r"addJavascriptInterface\(")
