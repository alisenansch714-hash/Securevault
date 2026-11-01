[app]

title = Secure Vault
package.name = securevault
package.domain = org.securevault

source.dir = .
source.include_exts = py,png,jpg,jpeg,kv,atlas,json,ttf

version = 2.0

requirements = python3,kivy,cryptography,pyjnius
p4a.branch = develop

orientation = portrait
fullscreen = 0

android.api = 35
android.minapi = 24
android.arch = arm64-v8a
android.add_src = android_src

android.gradle_dependencies = androidx.biometric:biometric:1.1.0
android.enable_androidx = True

android.permissions = USE_BIOMETRIC,USE_FINGERPRINT

android.accept_sdk_license = True

[buildozer]

log_level = 2
warn_on_root = 1
