import os
import json
import uuid
import hmac
import struct
import hashlib
from pathlib import Path

from kivy.app import App
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.core.window import Window
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.textinput import TextInput
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


Window.clearcolor = (0.025, 0.055, 0.11, 1)

BG = (0.025, 0.055, 0.11, 1)
PANEL = (0.055, 0.105, 0.19, 1)
BLUE = (0.10, 0.38, 0.75, 1)
LIGHT = (0.65, 0.82, 1, 1)
WHITE = (0.94, 0.96, 1, 1)


class SecureVault(App):

    def build(self):
        self.title = "Secure Vault"

        self.base = self.user_data_dir
        self.vault = os.path.join(self.base, "vault")
        self.config_file = os.path.join(
            self.base, "vault_config.json"
        )
        self.restore_folder = os.path.join(
            self.base, "Restored"
        )

        os.makedirs(self.vault, exist_ok=True)
        os.makedirs(self.restore_folder, exist_ok=True)

        self.password = None
        self.selected_vault = None
        self.selected_source = None

        self.config = None
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r") as f:
                    self.config = json.load(f)
            except Exception:
                self.config = None

        self.root_box = BoxLayout(
            orientation="vertical",
            padding=dp(18),
            spacing=dp(12)
        )
        self.show_login()
        return self.root_box

    def make_button(self, text, callback, height=52):
        btn = Button(
            text=text,
            size_hint_y=None,
            height=dp(height),
            background_normal="",
            background_color=BLUE,
            color=WHITE,
            font_size="16sp"
        )
        btn.bind(on_release=callback)
        return btn

    def make_label(self, text, size=16, color=WHITE):
        return Label(
            text=text,
            font_size=f"{size}sp",
            color=color,
            size_hint_y=None,
            height=dp(40),
            halign="center",
            valign="middle"
        )

    def make_password_input(self, hint):
        return TextInput(
            hint_text=hint,
            password=True,
            multiline=False,
            size_hint_y=None,
            height=dp(52),
            background_color=PANEL,
            foreground_color=WHITE,
            hint_text_color=LIGHT,
            cursor_color=WHITE,
            padding=dp(12)
        )

    def clear_screen(self):
        self.root_box.clear_widgets()

    def show_message(self, message):
        content = BoxLayout(
            orientation="vertical",
            padding=dp(12),
            spacing=dp(10)
        )
        content.add_widget(
            Label(text=message, color=WHITE)
        )
        popup = Popup(
            title="Secure Vault",
            content=content,
            size_hint=(0.88, 0.38),
            separator_color=BLUE
        )
        content.add_widget(
            self.make_button(
                "حسناً",
                lambda *_: popup.dismiss(),
                44
            )
        )
        popup.open()

    # ---------- Password and authentication ----------

    def derive_key(self, password, salt):
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            300000,
            dklen=32
        )

    def show_login(self):
        self.clear_screen()

        self.root_box.add_widget(
            self.make_label("SECURE VAULT", 27, LIGHT)
        )
        self.root_box.add_widget(
            self.make_label("الخزنة الآمنة", 22)
        )

        self.password_input = self.make_password_input(
            "كلمة المرور"
        )
        self.root_box.add_widget(self.password_input)

        if self.config is None:
            self.root_box.add_widget(
                self.make_button(
                    "إنشاء كلمة مرور",
                    self.create_password
                )
            )
            self.root_box.add_widget(
                self.make_label(
                    "أنشئ كلمة مرور لا تقل عن 8 أحرف",
                    13, LIGHT
                )
            )
        else:
            self.root_box.add_widget(
                self.make_button(
                    "فتح الخزنة",
                    self.login
                )
            )
            self.root_box.add_widget(
                self.make_label(
                    "أدخل كلمة المرور لفتح ملفاتك",
                    13, LIGHT
                )
            )

    def create_password(self, *_):
        password = self.password_input.text

        if len(password) < 8:
            self.show_message(
                "كلمة المرور يجب أن تكون 8 أحرف على الأقل."
            )
            return

        salt = os.urandom(16)
        key = self.derive_key(password, salt)

        verifier = hmac.new(
            key,
            b"SecureVaultPasswordCheck",
            hashlib.sha256
        ).hexdigest()

        self.config = {
            "salt": salt.hex(),
            "verifier": verifier,
            "version": 2
        }

        temporary = self.config_file + ".tmp"
        with open(temporary, "w") as f:
            json.dump(self.config, f)

        os.replace(temporary, self.config_file)

        self.password = password
        self.show_home()

    def login(self, *_):
        password = self.password_input.text

        try:
            salt = bytes.fromhex(self.config["salt"])
            key = self.derive_key(password, salt)

            verifier = hmac.new(
                key,
                b"SecureVaultPasswordCheck",
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(
                verifier, self.config["verifier"]
            ):
                self.show_message("كلمة المرور غير صحيحة.")
                return

            self.password = password
            self.show_home()

        except Exception:
            self.show_message("تعذر فتح الخزنة.")

    # ---------- Main screen ----------

    def show_home(self):
        self.clear_screen()

        self.root_box.add_widget(
            self.make_label("SECURE VAULT", 27, LIGHT)
        )
        self.root_box.add_widget(
            self.make_label("خزنتك الخاصة والآمنة", 17)
        )

        count = len([
            x for x in os.listdir(self.vault)
            if x.endswith(".vault")
        ])

        self.root_box.add_widget(
            self.make_label(
                f"عدد الملفات المحمية: {count}",
                16, LIGHT
            )
        )

        self.root_box.add_widget(
            self.make_button(
                "＋  إضافة صورة أو فيديو أو مستند",
                self.open_file_picker
            )
        )

        self.root_box.add_widget(
            self.make_button(
                "الملفات الموجودة في الخزنة",
                self.show_vault
            )
        )

        self.root_box.add_widget(
            self.make_button(
                "استعادة ملف",
                self.show_vault
            )
        )

        self.root_box.add_widget(
            self.make_button(
                "قفل الخزنة",
                self.lock_vault
            )
        )

        self.root_box.add_widget(
            self.make_label(
                "تشفير AES-256-GCM",
                12, LIGHT
            )
        )

    def lock_vault(self, *_):
        self.password = None
        self.selected_vault = None
        self.show_login()

    # ---------- File picker ----------

    def open_file_picker(self, *_):
        start = os.path.expanduser("~")

        if os.path.isdir("/storage/emulated/0"):
            start = "/storage/emulated/0"

        chooser = FileChooserListView(
            path=start,
            filters=["*"],
            dirselect=False
        )

        layout = BoxLayout(
            orientation="vertical",
            spacing=dp(8),
            padding=dp(8)
        )
        layout.add_widget(chooser)

        popup = Popup(
            title="اختر الملف",
            content=layout,
            size_hint=(0.96, 0.92)
        )

        def select_file(*_):
            if not chooser.selection:
                self.show_message("اختر ملفاً أولاً.")
                return

            self.selected_source = chooser.selection[0]
            popup.dismiss()
            self.confirm_original_action()

        layout.add_widget(
            self.make_button("اختيار الملف", select_file, 46)
        )
        layout.add_widget(
            self.make_button(
                "إلغاء",
                lambda *_: popup.dismiss(),
                42
            )
        )
        popup.open()

    # ---------- Encryption ----------

    def confirm_original_action(self):
        layout = BoxLayout(
            orientation="vertical",
            padding=dp(12),
            spacing=dp(10)
        )

        layout.add_widget(
            Label(
                text="ماذا تريد أن يحدث للملف الأصلي؟",
                color=WHITE
            )
        )

        popup = Popup(
            title="تأكيد العملية",
            content=layout,
            size_hint=(0.9, 0.45)
        )

        layout.add_widget(
            self.make_button(
                "الاحتفاظ بالأصل",
                lambda *_: (
                    popup.dismiss(),
                    self.encrypt_file(False)
                ),
                46
            )
        )

        layout.add_widget(
            self.make_button(
                "حذف الأصل بعد التحقق من التشفير",
                lambda *_: (
                    popup.dismiss(),
                    self.encrypt_file(True)
                ),
                46
            )
        )

        layout.add_widget(
            self.make_button(
                "إلغاء",
                lambda *_: popup.dismiss(),
                40
            )
        )

        popup.open()

    def encrypt_file(self, delete_original):
        source = self.selected_source

        if not source or not os.path.isfile(source):
            self.show_message("الملف غير موجود.")
            return

        if not self.password:
            self.show_message("الخزنة مقفلة.")
            return

        try:
            filename = os.path.basename(source)

            with open(source, "rb") as f:
                data = f.read()

            name = filename.encode("utf-8")

            plaintext = (
                struct.pack(">I", len(name))
                + name
                + data
            )

            salt = os.urandom(16)
            nonce = os.urandom(12)

            key = self.derive_key(self.password, salt)

            encrypted = AESGCM(key).encrypt(
                nonce, plaintext, b"SecureVault2"
            )

            output = (
                b"FVLT2"
                + salt
                + nonce
                + encrypted
            )

            destination = os.path.join(
                self.vault,
                uuid.uuid4().hex + ".vault"
            )

            temporary = destination + ".tmp"

            with open(temporary, "wb") as f:
                f.write(output)
                f.flush()
                os.fsync(f.fileno())

            # Verify encrypted file before committing it.
            with open(temporary, "rb") as f:
                check = f.read()

            check_key = self.derive_key(
                self.password, check[5:21]
            )

            recovered = AESGCM(check_key).decrypt(
                check[21:33],
                check[33:],
                b"SecureVault2"
            )

            if not hmac.compare_digest(
                hashlib.sha256(recovered).digest(),
                hashlib.sha256(plaintext).digest()
            ):
                raise ValueError("Verification failed")

            os.replace(temporary, destination)

            if delete_original:
                # Logical deletion only; flash storage may
                # retain recoverable physical data.
                os.remove(source)

            self.selected_source = None
            self.show_home()

            if delete_original:
                self.show_message(
                    "تم التشفير والتحقق وحذف الملف الأصلي."
                )
            else:
                self.show_message(
                    "تم التشفير بنجاح، والأصل محفوظ."
                )

        except Exception as error:
            try:
                if "temporary" in locals() and os.path.exists(temporary):
                    os.remove(temporary)
            except Exception:
                pass

            self.show_message(
                "تعذر تشفير الملف: " + str(error)
            )

    # ---------- Vault list and restore ----------

    def show_vault(self, *_):
        self.clear_screen()

        self.root_box.add_widget(
            self.make_label("ملفاتي المحمية", 24, LIGHT)
        )

        scroll = ScrollView()
        listing = GridLayout(
            cols=1,
            spacing=dp(8),
            size_hint_y=None,
            padding=dp(5)
        )
        listing.bind(
            minimum_height=listing.setter("height")
        )

        files = sorted([
            x for x in os.listdir(self.vault)
            if x.endswith(".vault")
        ])

        if not files:
            listing.add_widget(
                self.make_label("الخزنة فارغة", 16)
            )

        for index, name in enumerate(files, start=1):
            path = os.path.join(self.vault, name)

            btn = self.make_button(
                f"ملف محمي رقم {index}",
                lambda instance, p=path: self.select_vault(p),
                48
            )
            listing.add_widget(btn)

        scroll.add_widget(listing)
        self.root_box.add_widget(scroll)

        self.root_box.add_widget(
            self.make_button("العودة للرئيسية", self.show_home)
        )

    def select_vault(self, path):
        self.selected_vault = path

        layout = BoxLayout(
            orientation="vertical",
            padding=dp(10),
            spacing=dp(10)
        )

        popup = Popup(
            title="إدارة الملف",
            content=layout,
            size_hint=(0.88, 0.42)
        )

        layout.add_widget(
            self.make_button(
                "استعادة وفك التشفير",
                lambda *_: (
                    popup.dismiss(),
                    self.decrypt_file()
                ),
                46
            )
        )

        layout.add_widget(
            self.make_button(
                "حذف الملف من الخزنة",
                lambda *_: (
                    popup.dismiss(),
                    self.confirm_vault_delete()
                ),
                46
            )
        )

        layout.add_widget(
            self.make_button(
                "إلغاء",
                lambda *_: popup.dismiss(),
                40
            )
        )

        popup.open()

    def decrypt_file(self):
        try:
            path = self.selected_vault

            if not path or not os.path.isfile(path):
                raise ValueError("File not found")

            with open(path, "rb") as f:
                content = f.read()

            if content[:5] != b"FVLT2":
                raise ValueError("Invalid vault format")

            salt = content[5:21]
            nonce = content[21:33]
            encrypted = content[33:]

            key = self.derive_key(self.password, salt)

            plaintext = AESGCM(key).decrypt(
                nonce, encrypted, b"SecureVault2"
            )

            name_length = struct.unpack(
                ">I", plaintext[:4]
            )[0]

            if name_length == 0 or name_length > len(plaintext) - 4:
                raise ValueError("Invalid filename")

            filename = plaintext[4:4 + name_length].decode(
                "utf-8"
            )

            if (
                not filename
                or os.path.basename(filename) != filename
                or filename in (".", "..")
            ):
                raise ValueError("Invalid filename")

            data = plaintext[4 + name_length:]

            destination = os.path.join(
                self.restore_folder, filename
            )

            if os.path.exists(destination):
                base, ext = os.path.splitext(filename)
                destination = os.path.join(
                    self.restore_folder,
                    base + "_" + uuid.uuid4().hex[:8] + ext
                )

            with open(destination, "xb") as f:
                f.write(data)

            self.show_message(
                "تم فك التشفير بنجاح.\n"
                "مكان الملف:\n" + destination
            )

        except Exception:
            self.show_message(
                "فشل فك التشفير. تحقق من كلمة المرور "
                "وسلامة الملف."
            )

    def confirm_vault_delete(self):
        if not self.selected_vault:
            return

        layout = BoxLayout(
            orientation="vertical",
            padding=dp(10),
            spacing=dp(10)
        )

        popup = Popup(
            title="تأكيد الحذف",
            content=layout,
            size_hint=(0.88, 0.36)
        )

        layout.add_widget(
            Label(
                text="هل تريد حذف الملف المشفر نهائياً من الخزنة؟",
                color=WHITE
            )
        )

        def delete(*_):
            try:
                os.remove(self.selected_vault)
                self.selected_vault = None
                popup.dismiss()
                self.show_vault()
                self.show_message("تم حذف الملف المشفر.")
            except Exception:
                popup.dismiss()
                self.show_message("تعذر حذف الملف.")

        layout.add_widget(
            self.make_button("نعم، احذف", delete, 44)
        )
        layout.add_widget(
            self.make_button(
                "إلغاء",
                lambda *_: popup.dismiss(),
                40
            )
        )

        popup.open()


if __name__ == "__main__":
    SecureVault().run()
