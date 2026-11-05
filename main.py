import os
import json
import uuid
import hmac
import struct
import hashlib

from kivy.app import App
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
from kivy.utils import platform
from kivy.clock import mainthread
from kivy.core.text import LabelBase

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if platform == "android":
    from android import activity
    from jnius import autoclass
else:
    activity = None
    autoclass = None


# ---------- Colors ----------

Window.clearcolor = (0.025, 0.055, 0.11, 1)

BG = (0.025, 0.055, 0.11, 1)
PANEL = (0.055, 0.105, 0.19, 1)
BLUE = (0.10, 0.38, 0.75, 1)
LIGHT = (0.65, 0.82, 1, 1)
WHITE = (0.94, 0.96, 1, 1)


class SecureVault(App):

    # ---------- Application startup ----------

  def build(self):

        self.title = "Secure Vault"

        font_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "fonts",
            "NotoNaskhArabic-VariableFont_wght.ttf"
        )

        LabelBase.register(
            name="Arabic",
            fn_regular=font_path
        )

        self.base = self.user_data_dir

        self.vault = os.path.join(
            self.base, "vault"
        )

        self.imports_folder = os.path.join(
            self.base, "Imports"
        )

        self.config_file = os.path.join(
            self.base, "vault_config.json"
        )

        self.restore_folder = os.path.join(
            self.base, "Restored"
        )

        os.makedirs(self.vault, exist_ok=True)
        os.makedirs(self.imports_folder, exist_ok=True)
        os.makedirs(self.restore_folder, exist_ok=True)

        self.password = None

        self.selected_vault = None
        self.selected_source = None
        self.selected_source_uri = None
        self.selected_source_name = None

        self.config = None

        if os.path.exists(self.config_file):

            try:
                with open(
                    self.config_file,
                    "r",
                    encoding="utf-8"
                ) as f:

                    self.config = json.load(f)

            except Exception:
                self.config = None

        self.root_box = BoxLayout(
            orientation="vertical",
            padding=dp(18),
            spacing=dp(12)
        )

        if platform == "android":

            activity.bind(
                on_activity_result=self.on_activity_result
            )

        self.show_login()

        return self.root_box
    # ---------- Interface helpers ----------

    def make_button(self, text, callback, height=52):

        btn = Button(
            text=text,
            size_hint_y=None,
            height=dp(height),
            background_normal="",
            background_color=BLUE,
            color=WHITE,
            font_size="16sp",
            font_name="Arabic"
        )

        btn.bind(on_release=callback)

        return btn

    def make_label(self, text, size=16, color=WHITE):

        return Label(
            text=text,
            font_size=f"{size}sp",
            font_name="Arabic",
            color=color,
            size_hint_y=None,
            height=dp(42),
            halign="center",
            valign="middle"
        )
    def make_password_input(self, hint):

        return TextInput(
            hint_text=hint,
            password=True,
            multiline=False,
            font_name="Arabic",
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
            Label(
                text=message,
                font_name="Arabic",
                font_size="16sp",
                color=WHITE,
                halign="center",
                valign="middle"
            )
        )

        popup = Popup(
            title="Secure Vault",
            content=content,
            size_hint=(0.88, 0.42),
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

    # ---------- Encryption key ----------

    def derive_key(self, password, salt):

        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            300000,
            dklen=32
        )

    # ---------- Login screen ----------

    def show_login(self):

        self.clear_screen()

        self.root_box.add_widget(
            self.make_label(
                "SECURE VAULT",
                27,
                LIGHT
            )
        )

        self.root_box.add_widget(
            self.make_label(
                "الخزنة الآمنة",
                22
            )
        )

        self.password_input = self.make_password_input(
            "كلمة المرور"
        )

        self.root_box.add_widget(
            self.password_input
        )

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
                    13,
                    LIGHT
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
                    13,
                    LIGHT
                )
            )

    # ---------- Create password ----------

    def create_password(self, *_):

        password = self.password_input.text

        if len(password) < 8:

            self.show_message(
                "كلمة المرور يجب أن تكون 8 أحرف على الأقل."
            )

            return

        temporary = self.config_file + ".tmp"

        try:

            salt = os.urandom(16)

            key = self.derive_key(
                password,
                salt
            )

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

            with open(
                temporary,
                "w",
                encoding="utf-8"
            ) as f:

                json.dump(self.config, f)

                f.flush()
                os.fsync(f.fileno())

            os.replace(
                temporary,
                self.config_file
            )

            self.password = password

            self.show_home()

        except Exception as error:

            if os.path.exists(temporary):

                try:
                    os.remove(temporary)
                except Exception:
                    pass

            self.show_message(
                "تعذر إنشاء كلمة المرور: " + str(error)
            )

    # ---------- Login ----------

    def login(self, *_):

        password = self.password_input.text

        try:

            salt = bytes.fromhex(
                self.config["salt"]
            )

            key = self.derive_key(
                password,
                salt
            )

            verifier = hmac.new(
                key,
                b"SecureVaultPasswordCheck",
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(
                verifier,
                self.config["verifier"]
            ):

                self.show_message(
                    "كلمة المرور غير صحيحة."
                )

                return

            self.password = password

            self.show_home()

        except Exception:

            self.show_message(
                "تعذر فتح الخزنة."
            )

    # ---------- Home screen ----------

    def show_home(self):

        self.clear_screen()

        self.root_box.add_widget(
            self.make_label(
                "SECURE VAULT",
                27,
                LIGHT
            )
        )

        self.root_box.add_widget(
            self.make_label(
                "خزنتك الخاصة والآمنة",
                17
            )
        )

        count = len([
            name for name in os.listdir(self.vault)
            if name.endswith(".vault")
        ])

        self.root_box.add_widget(
            self.make_label(
                f"عدد الملفات المحمية: {count}",
                16,
                LIGHT
            )
        )

        self.root_box.add_widget(
            self.make_button(
                "＋ إضافة صورة أو فيديو أو مستند",
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
                12,
                LIGHT
            )
        )

    # ---------- Lock vault ----------

    def lock_vault(self, *_):

        self.password = None

        self.selected_vault = None
        self.selected_source = None
        self.selected_source_uri = None
        self.selected_source_name = None

        self.show_login()

    # ---------- File picker ----------

    def open_file_picker(self, *_):

        if platform == "android":

            try:

                Intent = autoclass(
                    "android.content.Intent"
                )

                PythonActivity = autoclass(
                    "org.kivy.android.PythonActivity"
                )

                intent = Intent(
                    Intent.ACTION_OPEN_DOCUMENT
                )

                intent.addCategory(
                    Intent.CATEGORY_OPENABLE
                )

                intent.setType("*/*")

                flags = (
                    Intent.FLAG_GRANT_READ_URI_PERMISSION
                    | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                    | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
                )

                intent.addFlags(flags)

                PythonActivity.mActivity.startActivityForResult(
                    intent,
                    1001
                )

            except Exception as error:

                self.show_message(
                    "تعذر فتح الملفات: " + str(error)
                )

        else:

            self.open_windows_file_picker()

    # ---------- Android file result ----------

    @mainthread
    def on_activity_result(
        self,
        request_code,
        result_code,
        intent
    ):

        if request_code != 1001:
            return

        if result_code != -1 or intent is None:

            self.show_message(
                "لم يتم اختيار ملف."
            )

            return

        temporary_path = None

        try:

            uri = intent.getData()

            if uri is None:

                self.show_message(
                    "تعذر الوصول إلى الملف."
                )

                return

            PythonActivity = autoclass(
                "org.kivy.android.PythonActivity"
            )

            FileBridge = autoclass(
                "org.securevault.FileBridge"
            )

            context = PythonActivity.mActivity

            # محاولة الاحتفاظ بإذن الوصول للملف

            try:

                Intent = autoclass(
                    "android.content.Intent"
                )

                permission_flags = (
                    intent.getFlags()
                    & (
                        Intent.FLAG_GRANT_READ_URI_PERMISSION
                        | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                    )
                )

                context.getContentResolver().takePersistableUriPermission(
                    uri,
                    permission_flags
                )

            except Exception:
                pass

            filename = str(
                FileBridge.getDisplayName(
                    context,
                    uri
                )
            )

            filename = os.path.basename(filename)

            if not filename or filename in (".", ".."):
                filename = "selected_file"

            temporary_path = os.path.join(
                self.imports_folder,
                uuid.uuid4().hex + "_" + filename
            )

            FileBridge.copyUriToFile(
                context,
                uri,
                temporary_path
            )

            if not os.path.isfile(temporary_path):

                raise ValueError(
                    "File copy failed"
                )

            self.selected_source = temporary_path

            self.selected_source_uri = uri

            self.selected_source_name = filename

            self.confirm_original_action()

        except Exception as error:

            if (
                temporary_path
                and os.path.exists(temporary_path)
            ):

                try:
                    os.remove(temporary_path)
                except Exception:
                    pass

            self.show_message(
                "تعذر استيراد الملف: " + str(error)
            )

    # ---------- Windows file picker ----------

    def open_windows_file_picker(self):

        chooser = FileChooserListView(
            path=os.path.expanduser("~"),
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
    title_font="Arabic",
    content=layout,
    size_hint=(0.96, 0.92)
)

        def select_file(*_):

            if not chooser.selection:

                self.show_message(
                    "اختر ملفاً أولاً."
                )

                return

            path = chooser.selection[0]

            if not os.path.isfile(path):

                self.show_message(
                    "الاختيار ليس ملفاً صالحاً."
                )

                return

            self.selected_source = path

            self.selected_source_uri = None

            self.selected_source_name = os.path.basename(path)

            popup.dismiss()

            self.confirm_original_action()

        layout.add_widget(
            self.make_button(
                "اختيار الملف",
                select_file,
                46
            )
        )

        layout.add_widget(
            self.make_button(
                "إلغاء",
                lambda *_: popup.dismiss(),
                42
            )
        )

        popup.open()

    # ---------- Original file confirmation ----------

    def confirm_original_action(self):

        layout = BoxLayout(
            orientation="vertical",
            padding=dp(12),
            spacing=dp(10)
        )

     Label(
    text="ماذا تريد أن يحدث للملف الأصلي؟",
    font_name="Arabic",
    font_size="16sp",
    color=WHITE,
    halign="center"
)
        )

       popup = Popup(
    title="تأكيد العملية",
    title_font="Arabic",
    content=layout,
    size_hint=(0.9, 0.48)
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

    # ---------- Encryption ----------

    def encrypt_file(self, delete_original):

        source = self.selected_source

        if not source or not os.path.isfile(source):

            self.show_message(
                "الملف غير موجود."
            )

            return

        if not self.password:

            self.show_message(
                "الخزنة مقفلة."
            )

            return

        encrypted_temp = None

        try:

            filename = (
                self.selected_source_name
                or os.path.basename(source)
            )

            filename = os.path.basename(filename)

            if not filename or filename in (".", ".."):

                raise ValueError(
                    "اسم الملف غير صالح."
                )

            with open(source, "rb") as f:
                data = f.read()

            encoded_name = filename.encode("utf-8")

            plaintext = (
                struct.pack(">I", len(encoded_name))
                + encoded_name
                + data
            )

            salt = os.urandom(16)

            nonce = os.urandom(12)

            key = self.derive_key(
                self.password,
                salt
            )

            encrypted = AESGCM(key).encrypt(
                nonce,
                plaintext,
                b"SecureVault2"
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

            encrypted_temp = destination + ".tmp"

            with open(encrypted_temp, "wb") as f:

                f.write(output)

                f.flush()

                os.fsync(f.fileno())

            # التحقق من نجاح التشفير

            with open(encrypted_temp, "rb") as f:
                check = f.read()

            if len(check) < 33 or check[:5] != b"FVLT2":

                raise ValueError(
                    "تعذر التحقق من الملف المشفر."
                )

            check_key = self.derive_key(
                self.password,
                check[5:21]
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

                raise ValueError(
                    "فشل التحقق من التشفير."
                )

            os.replace(
                encrypted_temp,
                destination
            )

            encrypted_temp = None

            # حذف الأصل عند طلب المستخدم

            original_deleted = False

            if delete_original:

                if (
                    platform == "android"
                    and self.selected_source_uri is not None
                ):

                    try:

                        PythonActivity = autoclass(
                            "org.kivy.android.PythonActivity"
                        )

                        FileBridge = autoclass(
                            "org.securevault.FileBridge"
                        )

                        original_deleted = bool(
                            FileBridge.deleteUri(
                                PythonActivity.mActivity,
                                self.selected_source_uri
                            )
                        )

                    except Exception:

                        original_deleted = False

                else:

                    try:

                        os.remove(source)

                        original_deleted = True

                    except Exception:

                        original_deleted = False

            # حذف النسخة المؤقتة داخل التطبيق

            if platform == "android" or not delete_original:

                try:

                    if os.path.exists(source):
                        os.remove(source)

                except Exception:
                    pass

            self.selected_source = None
            self.selected_source_uri = None
            self.selected_source_name = None

            self.show_home()

            if not delete_original:

                self.show_message(
                    "تم التشفير والتحقق بنجاح. "
                    "الملف الأصلي محفوظ."
                )

            elif original_deleted:

                self.show_message(
                    "تم التشفير والتحقق وحذف الأصل. "
                    "الحذف من ذاكرة الفلاش ليس مسحاً مادياً مضموناً."
                )

            else:

                self.show_message(
                    "تم التشفير والتحقق بنجاح، "
                    "لكن تعذر حذف الملف الأصلي. "
                    "تحقق من مكانه واحذفه يدوياً إذا رغبت."
                )

        except Exception as error:

            if (
                encrypted_temp
                and os.path.exists(encrypted_temp)
            ):

                try:
                    os.remove(encrypted_temp)
                except Exception:
                    pass

            self.show_message(
                "تعذر تشفير الملف: " + str(error)
            )

    # ---------- Vault files ----------

    def show_vault(self, *_):

        self.clear_screen()

        self.root_box.add_widget(
            self.make_label(
                "ملفاتي المحمية",
                24,
                LIGHT
            )
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
            name for name in os.listdir(self.vault)
            if name.endswith(".vault")
        ])

        if not files:

            listing.add_widget(
                self.make_label(
                    "الخزنة فارغة",
                    16
                )
            )

        for index, name in enumerate(files, start=1):

            path = os.path.join(
                self.vault,
                name
            )

            listing.add_widget(
                self.make_button(
                    f"ملف محمي رقم {index}",
                    lambda instance, p=path: self.select_vault(p),
                    48
                )
            )

        scroll.add_widget(listing)

        self.root_box.add_widget(scroll)

        self.root_box.add_widget(
            self.make_button(
                "العودة للرئيسية",
                self.show_home
            )
        )

    # ---------- Select vault file ----------

    def select_vault(self, path):

        self.selected_vault = path

        layout = BoxLayout(
            orientation="vertical",
            padding=dp(10),
            spacing=dp(10)
        )

       popup = Popup(
    title="إدارة الملف",
    title_font="Arabic",
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

    # ---------- Decryption and restore ----------

    def decrypt_file(self):

        try:

            if not self.password:
                raise ValueError("الخزنة مقفلة.")

            path = self.selected_vault

            if not path or not os.path.isfile(path):
                raise ValueError("الملف غير موجود.")

            with open(path, "rb") as f:
                content = f.read()

            if len(content) < 33 or content[:5] != b"FVLT2":
                raise ValueError("صيغة الملف غير صحيحة.")

            salt = content[5:21]

            nonce = content[21:33]

            encrypted = content[33:]

            key = self.derive_key(
                self.password,
                salt
            )

            plaintext = AESGCM(key).decrypt(
                nonce,
                encrypted,
                b"SecureVault2"
            )

            if len(plaintext) < 4:
                raise ValueError("بيانات الملف غير مكتملة.")

            name_length = struct.unpack(
                ">I",
                plaintext[:4]
            )[0]

            if name_length == 0 or name_length > len(plaintext) - 4:
                raise ValueError("اسم الملف غير صالح.")

            filename = plaintext[
                4:4 + name_length
            ].decode("utf-8")

            if (
                not filename
                or os.path.basename(filename) != filename
                or filename in (".", "..")
            ):

                raise ValueError("اسم الملف غير صالح.")

            data = plaintext[4 + name_length:]

            destination = os.path.join(
                self.restore_folder,
                filename
            )

            if os.path.exists(destination):

                base, ext = os.path.splitext(filename)

                destination = os.path.join(
                    self.restore_folder,
                    base + "_" + uuid.uuid4().hex[:8] + ext
                )

            with open(destination, "xb") as f:

                f.write(data)

                f.flush()

                os.fsync(f.fileno())

            self.show_message(
                "تم فك التشفير بنجاح.\n"
                "مكان الملف:\n"
                + destination
            )

        except Exception:

            self.show_message(
                "فشل فك التشفير. تحقق من كلمة المرور "
                "وسلامة الملف."
            )

    # ---------- Delete vault file ----------

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
    title_font="Arabic",
    content=layout,
    size_hint=(0.88, 0.38)
)
        )

        layout.add_widget(
           Label(
    text="هل تريد حذف الملف المشفر من الخزنة؟",
    font_name="Arabic",
    font_size="16sp",
    color=WHITE,
    halign="center"
)
        )

        def delete(*_):

            try:

                if (
                    self.selected_vault
                    and os.path.isfile(self.selected_vault)
                ):

                    os.remove(self.selected_vault)

                self.selected_vault = None

                popup.dismiss()

                self.show_vault()

                self.show_message(
                    "تم حذف الملف المشفر من الخزنة."
                )

            except Exception:

                popup.dismiss()

                self.show_message(
                    "تعذر حذف الملف."
                )

        layout.add_widget(
            self.make_button(
                "نعم، احذف",
                delete,
                44
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


# ---------- Run application ----------

if __name__ == "__main__":

    SecureVault().run()
