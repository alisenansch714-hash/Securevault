import os
import uuid
import struct
import hashlib

from kivy.app import App
from kivy.lang import Builder
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.textinput import TextInput
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.scrollview import ScrollView

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from android.permissions import request_permissions, Permission
    ANDROID = True
except ImportError:
    ANDROID = False


KV = """
BoxLayout:
    orientation: "vertical"
    padding: 10
    spacing: 8

    Label:
        text: "الخزنة الآمنة"
        font_size: "26sp"
        size_hint_y: None
        height: "55dp"

    TextInput:
        id: password
        hint_text: "أدخل كلمة المرور (8 أحرف على الأقل)"
        password: True
        multiline: False
        size_hint_y: None
        height: "48dp"

    Label:
        text: "اختر ملفاً لحمايته:"
        size_hint_y: None
        height: "30dp"

    FileChooserListView:
        id: chooser
        path: app.files_path
        dirselect: False
        filters: ["*"]

    Button:
        text: "تشفير وإضافة إلى الخزنة"
        size_hint_y: None
        height: "50dp"
        on_release: app.encrypt_file()

    Label:
        text: "الملفات الموجودة في الخزنة:"
        size_hint_y: None
        height: "35dp"

    ScrollView:
        size_hint_y: 0.30

        GridLayout:
            id: vault_list
            cols: 1
            size_hint_y: None
            height: self.minimum_height
            spacing: 5

    Button:
        text: "فك تشفير الملف المحدد"
        size_hint_y: None
        height: "50dp"
        on_release: app.decrypt_file()

    Button:
        text: "تحديث الخزنة"
        size_hint_y: None
        height: "42dp"
        on_release: app.refresh_vault()
"""


class SecureVault(App):

    def build(self):
        self.title = "الخزنة الآمنة"

        self.vault_path = os.path.join(
            self.user_data_dir, "vault"
        )
        os.makedirs(self.vault_path, exist_ok=True)

        self.files_path = (
            "/storage/emulated/0"
            if ANDROID else os.path.expanduser("~")
        )

        self.selected_vault = None
        self.root_widget = Builder.load_string(KV)

        return self.root_widget

    def on_start(self):
        if ANDROID:
            request_permissions([
                Permission.READ_EXTERNAL_STORAGE,
                Permission.WRITE_EXTERNAL_STORAGE
            ])

        self.refresh_vault()

    def show_message(self, message):
        popup = Popup(
            title="الخزنة الآمنة",
            content=Label(
                text=message,
                halign="center"
            ),
            size_hint=(0.85, 0.35)
        )
        popup.open()

    def get_key(self, password, salt):
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            300000,
            dklen=32
        )

    def encrypt_file(self):
        password = self.root_widget.ids.password.text
        selected = self.root_widget.ids.chooser.selection

        if len(password) < 8:
            self.show_message("كلمة المرور يجب أن تكون 8 أحرف على الأقل.")
            return

        if not selected:
            self.show_message("اختر ملفاً أولاً.")
            return

        source = selected[0]

        try:
            if not os.path.isfile(source):
                self.show_message("الملف المحدد غير صالح.")
                return

            with open(source, "rb") as file:
                data = file.read()

            filename = os.path.basename(source).encode("utf-8")

            plaintext = (
                struct.pack(">I", len(filename))
                + filename
                + data
            )

            salt = os.urandom(16)
            nonce = os.urandom(12)
            key = self.get_key(password, salt)

            encrypted = AESGCM(key).encrypt(
                nonce, plaintext, None
            )

            output = (
                b"FVLT1"
                + salt
                + nonce
                + encrypted
            )

            destination = os.path.join(
                self.vault_path,
                uuid.uuid4().hex + ".vault"
            )

            with open(destination, "wb") as file:
                file.write(output)

            self.refresh_vault()

            self.show_message(
                "تم تشفير الملف وحفظ نسخة آمنة منه."
                "\nالملف الأصلي لم يتم حذفه."
            )

        except Exception as error:
            self.show_message("تعذر تشفير الملف: " + str(error))

    def refresh_vault(self):
        if not self.root_widget:
            return

        container = self.root_widget.ids.vault_list
        container.clear_widgets()
        self.selected_vault = None

        try:
            files = [
                name for name in os.listdir(self.vault_path)
                if name.endswith(".vault")
            ]

            for name in files:
                path = os.path.join(self.vault_path, name)

                button = Button(
                    text="ملف محمي: " + name[:12],
                    size_hint_y=None,
                    height=45
                )

                button.bind(
                    on_release=lambda btn, p=path:
                    self.select_vault(p, btn)
                )

                container.add_widget(button)

            if not files:
                container.add_widget(
                    Label(
                        text="الخزنة فارغة",
                        size_hint_y=None,
                        height=40
                    )
                )

        except Exception as error:
            self.show_message("تعذر قراءة الخزنة: " + str(error))

    def select_vault(self, path, button):
        self.selected_vault = path
        self.show_message("تم تحديد الملف.")

    def decrypt_file(self):
        password = self.root_widget.ids.password.text

        if len(password) < 8:
            self.show_message("أدخل كلمة المرور الصحيحة.")
            return

        if not self.selected_vault:
            self.show_message("حدد ملفاً من الخزنة أولاً.")
            return

        try:
            with open(self.selected_vault, "rb") as file:
                content = file.read()

            if content[:5] != b"FVLT1":
                raise ValueError("صيغة الملف غير صحيحة.")

            salt = content[5:21]
            nonce = content[21:33]
            encrypted = content[33:]

            key = self.get_key(password, salt)

            plaintext = AESGCM(key).decrypt(
                nonce, encrypted, None
            )

            name_length = struct.unpack(
                ">I", plaintext[:4]
            )[0]

            filename = plaintext[4:4 + name_length].decode("utf-8")
            data = plaintext[4 + name_length:]

            if not filename or os.path.basename(filename) != filename:
                raise ValueError("اسم الملف غير صالح.")

            output_folder = os.path.join(
                "/storage/emulated/0", "Download"
            ) if ANDROID else os.path.join(
                os.path.expanduser("~"), "Downloads"
            )

            os.makedirs(output_folder, exist_ok=True)

            destination = os.path.join(
                output_folder, filename
            )

            if os.path.exists(destination):
                base, ext = os.path.splitext(filename)
                destination = os.path.join(
                    output_folder,
                    base + "_" + uuid.uuid4().hex[:8] + ext
                )

            with open(destination, "wb") as file:
                file.write(data)

            self.show_message(
                "تم فك التشفير بنجاح.\n"
                "تم حفظ الملف في مجلد Downloads."
            )

        except Exception:
            self.show_message(
                "فشل فك التشفير. تأكد من كلمة المرور "
                "أو سلامة الملف."
            )


if __name__ == "__main__":
    SecureVault().run()
