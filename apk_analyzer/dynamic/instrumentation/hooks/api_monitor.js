/**
 * Sensitive API Monitoring Script
 *
 * Monitors:
 * - SharedPreferences access
 * - ContentProvider queries
 * - Cryptographic operations
 * - Log output
 * - File operations
 * - Network operations
 * - Intent operations
 * - WebView operations
 */

Java.perform(function() {
    console.log("[*] API Monitor loaded");

    // ===== SharedPreferences Monitoring =====
    try {
        var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");

        SharedPreferencesImpl.getString.overload("java.lang.String", "java.lang.String").implementation = function(key, defValue) {
            var value = this.getString(key, defValue);

            // Check for sensitive keys
            var keyLower = key.toLowerCase();
            if (keyLower.indexOf("token") >= 0 || keyLower.indexOf("password") >= 0 ||
                keyLower.indexOf("secret") >= 0 || keyLower.indexOf("api_key") >= 0 ||
                keyLower.indexOf("session") >= 0 || keyLower.indexOf("auth") >= 0) {
                send({
                    class: "SharedPreferences",
                    method: "getString",
                    args: [key, value ? value.substring(0, 50) : null],
                    extra: {type: "sensitive_pref", severity: "high"}
                });
            }
            return value;
        };

        var Editor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        Editor.putString.overload("java.lang.String", "java.lang.String").implementation = function(key, value) {
            var keyLower = key.toLowerCase();
            if (keyLower.indexOf("token") >= 0 || keyLower.indexOf("password") >= 0 ||
                keyLower.indexOf("secret") >= 0) {
                send({
                    class: "SharedPreferences$Editor",
                    method: "putString",
                    args: [key, value ? "[REDACTED]" : null],
                    extra: {type: "sensitive_pref_write", severity: "high"}
                });
            }
            return this.putString(key, value);
        };

        console.log("[+] SharedPreferences monitoring installed");
    } catch(e) {
        console.log("[-] SharedPreferences monitoring failed: " + e);
    }

    // ===== ContentProvider Query Monitoring =====
    try {
        var ContentResolver = Java.use("android.content.ContentResolver");

        ContentResolver.query.overload("android.net.Uri", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String").implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
            send({
                class: "ContentResolver",
                method: "query",
                args: [uri.toString(), selection],
                extra: {type: "content_query"}
            });
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };

        ContentResolver.insert.overload("android.net.Uri", "android.content.ContentValues").implementation = function(uri, values) {
            send({
                class: "ContentResolver",
                method: "insert",
                args: [uri.toString()],
                extra: {type: "content_insert"}
            });
            return this.insert(uri, values);
        };

        ContentResolver.update.overload("android.net.Uri", "android.content.ContentValues", "java.lang.String", "[Ljava.lang.String;").implementation = function(uri, values, where, selectionArgs) {
            send({
                class: "ContentResolver",
                method: "update",
                args: [uri.toString(), where],
                extra: {type: "content_update"}
            });
            return this.update(uri, values, where, selectionArgs);
        };

        ContentResolver.delete.overload("android.net.Uri", "java.lang.String", "[Ljava.lang.String;").implementation = function(uri, where, selectionArgs) {
            send({
                class: "ContentResolver",
                method: "delete",
                args: [uri.toString(), where],
                extra: {type: "content_delete"}
            });
            return this.delete(uri, where, selectionArgs);
        };

        console.log("[+] ContentResolver monitoring installed");
    } catch(e) {
        console.log("[-] ContentResolver monitoring failed: " + e);
    }

    // ===== Cryptographic Operations Monitoring =====
    try {
        var Cipher = Java.use("javax.crypto.Cipher");

        Cipher.doFinal.overload("[B").implementation = function(input) {
            var algorithm = this.getAlgorithm();
            send({
                class: "Cipher",
                method: "doFinal",
                args: [input.length + " bytes"],
                extra: {type: "crypto_operation", algorithm: algorithm}
            });
            return this.doFinal(input);
        };

        Cipher.getInstance.overload("java.lang.String").implementation = function(transformation) {
            send({
                class: "Cipher",
                method: "getInstance",
                args: [transformation],
                extra: {type: "crypto_init"}
            });
            return this.getInstance(transformation);
        };

        console.log("[+] Crypto monitoring installed");
    } catch(e) {}

    // ===== SecretKeySpec Monitoring =====
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");

        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function(key, algorithm) {
            send({
                class: "SecretKeySpec",
                method: "$init",
                args: [key.length + " byte key", algorithm],
                extra: {type: "crypto_key", severity: "high"}
            });
            return this.$init(key, algorithm);
        };

        console.log("[+] SecretKeySpec monitoring installed");
    } catch(e) {}

    // ===== Log Output Monitoring =====
    try {
        var Log = Java.use("android.util.Log");
        var sensitivePatterns = ["password", "token", "secret", "api_key", "auth", "credit", "ssn"];

        ["d", "i", "w", "e", "v"].forEach(function(level) {
            Log[level].overload("java.lang.String", "java.lang.String").implementation = function(tag, msg) {
                var lowerMsg = msg.toLowerCase();
                var isSensitive = false;

                for (var i = 0; i < sensitivePatterns.length; i++) {
                    if (lowerMsg.indexOf(sensitivePatterns[i]) >= 0) {
                        isSensitive = true;
                        break;
                    }
                }

                if (isSensitive) {
                    send({
                        class: "Log",
                        method: level,
                        args: [tag, msg.substring(0, 200)],
                        extra: {type: "sensitive_log", severity: "high"}
                    });
                }
                return this[level](tag, msg);
            };
        });

        console.log("[+] Log monitoring installed");
    } catch(e) {}

    // ===== WebView Operations Monitoring =====
    try {
        var WebView = Java.use("android.webkit.WebView");

        WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
            send({
                class: "WebView",
                method: "loadUrl",
                args: [url],
                extra: {type: "webview_load"}
            });
            return this.loadUrl(url);
        };

        WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function(url, headers) {
            send({
                class: "WebView",
                method: "loadUrl",
                args: [url],
                extra: {type: "webview_load_headers", hasHeaders: headers !== null}
            });
            return this.loadUrl(url, headers);
        };

        WebView.loadData.overload("java.lang.String", "java.lang.String", "java.lang.String").implementation = function(data, mimeType, encoding) {
            send({
                class: "WebView",
                method: "loadData",
                args: [data.substring(0, 100), mimeType, encoding],
                extra: {type: "webview_data"}
            });
            return this.loadData(data, mimeType, encoding);
        };

        WebView.addJavascriptInterface.overload("java.lang.Object", "java.lang.String").implementation = function(obj, name) {
            send({
                class: "WebView",
                method: "addJavascriptInterface",
                args: [obj.getClass().getName(), name],
                extra: {type: "js_interface", severity: "critical"}
            });
            return this.addJavascriptInterface(obj, name);
        };

        WebView.evaluateJavascript.overload("java.lang.String", "android.webkit.ValueCallback").implementation = function(script, callback) {
            send({
                class: "WebView",
                method: "evaluateJavascript",
                args: [script.substring(0, 200)],
                extra: {type: "js_evaluation", severity: "high"}
            });
            return this.evaluateJavascript(script, callback);
        };

        console.log("[+] WebView monitoring installed");
    } catch(e) {}

    // ===== Intent Monitoring =====
    try {
        var Intent = Java.use("android.content.Intent");
        var Activity = Java.use("android.app.Activity");

        Activity.startActivity.overload("android.content.Intent").implementation = function(intent) {
            send({
                class: "Activity",
                method: "startActivity",
                extra: {
                    action: intent.getAction(),
                    data: intent.getDataString(),
                    component: intent.getComponent() ? intent.getComponent().flattenToString() : null,
                    type: "intent_start"
                }
            });
            return this.startActivity(intent);
        };

        Activity.startActivityForResult.overload("android.content.Intent", "int").implementation = function(intent, requestCode) {
            send({
                class: "Activity",
                method: "startActivityForResult",
                args: [requestCode],
                extra: {
                    action: intent.getAction(),
                    data: intent.getDataString(),
                    type: "intent_for_result"
                }
            });
            return this.startActivityForResult(intent, requestCode);
        };

        console.log("[+] Intent monitoring installed");
    } catch(e) {}

    // ===== File Operations Monitoring =====
    try {
        var FileInputStream = Java.use("java.io.FileInputStream");
        var FileOutputStream = Java.use("java.io.FileOutputStream");

        FileInputStream.$init.overload("java.io.File").implementation = function(file) {
            var path = file.getAbsolutePath();
            if (path.indexOf("shared_prefs") >= 0 || path.indexOf("databases") >= 0 ||
                path.indexOf("sdcard") >= 0) {
                send({
                    class: "FileInputStream",
                    method: "$init",
                    args: [path],
                    extra: {type: "file_read"}
                });
            }
            return this.$init(file);
        };

        FileOutputStream.$init.overload("java.io.File").implementation = function(file) {
            var path = file.getAbsolutePath();
            send({
                class: "FileOutputStream",
                method: "$init",
                args: [path],
                extra: {type: "file_write"}
            });
            return this.$init(file);
        };

        console.log("[+] File operation monitoring installed");
    } catch(e) {}

    send({
        class: "APIMonitor",
        method: "init",
        extra: {status: "active", message: "API monitoring activated"}
    });

    console.log("[*] API Monitor complete");
});
