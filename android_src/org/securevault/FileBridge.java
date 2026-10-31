package org.securevault;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;

public class FileBridge {

    public static String getDisplayName(
            Context context, Uri uri) {

        Cursor cursor = null;

        try {
            cursor = context.getContentResolver().query(
                uri,
                new String[]{OpenableColumns.DISPLAY_NAME},
                null,
                null,
                null
            );

            if (cursor != null && cursor.moveToFirst()) {
                int index = cursor.getColumnIndex(
                    OpenableColumns.DISPLAY_NAME
                );

                if (index >= 0) {
                    return cursor.getString(index);
                }
            }
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }

        return "selected_file";
    }

    public static void copyUriToFile(
            Context context,
            Uri uri,
            String destinationPath) throws IOException {

        File destination = new File(destinationPath);

        File parent = destination.getParentFile();

        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        try (
            InputStream input =
                context.getContentResolver().openInputStream(uri);

            FileOutputStream output =
                new FileOutputStream(destination)
        ) {
            if (input == null) {
                throw new IOException("Cannot open selected file");
            }

            byte[] buffer = new byte[65536];
            int count;

            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
            }

            output.flush();
            output.getFD().sync();
       } catch (IOException | RuntimeException error) {
    destination.delete();
    throw error;
}
        }
    }
}

package org.securevault;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;

public class FileBridge {

    public static String getDisplayName(
            Context context, Uri uri) {

        Cursor cursor = null;

        try {
            cursor = context.getContentResolver().query(
                uri,
                new String[]{OpenableColumns.DISPLAY_NAME},
                null,
                null,
                null
            );

            if (cursor != null && cursor.moveToFirst()) {
                int index = cursor.getColumnIndex(
                    OpenableColumns.DISPLAY_NAME
                );

                if (index >= 0) {
                    return cursor.getString(index);
                }
            }
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }

        return "selected_file";
    }

    public static void copyUriToFile(
            Context context,
            Uri uri,
            String destinationPath) throws IOException {

        File destination = new File(destinationPath);

        File parent = destination.getParentFile();

        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        try (
            InputStream input =
                context.getContentResolver().openInputStream(uri);

            FileOutputStream output =
                new FileOutputStream(destination)
        ) {
            if (input == null) {
                throw new IOException("Cannot open selected file");
            }

            byte[] buffer = new byte[65536];
            int count;

            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
            }

            output.flush();
            output.getFD().sync();
        } catch (Exception error) {
            destination.delete();
            throw error;
        }
    }
}
