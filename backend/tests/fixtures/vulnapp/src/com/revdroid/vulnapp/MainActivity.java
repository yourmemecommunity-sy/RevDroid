package com.revdroid.vulnapp;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** Deliberately insecure code for RevDroid tests. Do not copy any of this into a real app. */
public class MainActivity extends Activity {
    // planted secrets (all fake)
    static final String AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
    static final String API_KEY = "sk_test_51RevDroidFakeKey0000";
    static final String ADMIN_PASSWORD = "Sup3rS3cret!";
    static final String PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEfake\n-----END RSA PRIVATE KEY-----";
    static final String LOGIN_URL = "http://api.vulnbank.example.com/login";
    static final String STATUS_URL = "https://status.vulnbank.example.com/v1/ping";
    static final String BACKUP_SERVER = "203.0.113.42";
    static final String PASSWORD_LABEL = "password"; // placeholder: must NOT be flagged

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView web = new WebView(this);
        web.getSettings().setJavaScriptEnabled(true);
        web.addJavascriptInterface(new Bridge(), "Android");
        web.getSettings().setAllowUniversalAccessFromFileURLs(true);
        web.loadUrl(LOGIN_URL);
        Log.d("VulnBank", "user password is " + ADMIN_PASSWORD);
        getSharedPreferences("prefs", Context.MODE_WORLD_READABLE).edit().putString("k", "v").apply();
        setContentView(web);
    }

    static String md5(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(s.getBytes()));
    }

    static byte[] encrypt(byte[] data) throws Exception {
        SecretKeySpec key = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }

    static byte[] encryptCbc(byte[] data, SecretKeySpec key) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}));
        return c.doFinal(data);
    }

    static void trustEverything() throws Exception {
        TrustManager[] all = new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }

            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }};
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, all, null);
        HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
    }

    static class Bridge {
        @JavascriptInterface
        public String token() {
            return "session";
        }
    }
}
