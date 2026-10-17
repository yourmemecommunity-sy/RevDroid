package com.revdroid.vulnapp;

import android.app.Activity;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;
import android.os.IBinder;

/** Component stubs referenced by the fixture manifest. */
final class Components {
    private Components() {
    }
}

class TransferActivity extends Activity {
}

class SyncService extends Service {
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}

class PrivateService extends SyncService {
}

class GuardedService extends SyncService {
}

class SmsReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
    }
}

class NotesProvider extends ContentProvider {
    private SQLiteDatabase db;

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] args, String sort) {
        // planted SQL injection
        return db.rawQuery("SELECT * FROM notes WHERE owner = '" + selection + "'", null);
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] args) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] args) {
        return 0;
    }
}
