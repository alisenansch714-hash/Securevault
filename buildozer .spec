[app]

title = Secure Vault
package.name = securevault
package.domain = org.securevault

source.dir = .
source.include_exts = py,png,jpg,jpeg,kv,atlas,json,ttf

version = 1.0

requirements = python3,kivy,cryptography,pyjnius
android.arch = arm64-v8a

orientation = portrait
fullscreen = 0

android.permissions = READ_MEDIA_IMAGES,READ_MEDIA_VIDEO,READ_MEDIA_AUDIO

android.api = 35
android.minapi = 23

[buildozer]

log_level = 2
warn_on_root = 1
