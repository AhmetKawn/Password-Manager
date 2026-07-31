import os
import sqlite3
import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
import secrets
import string
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_FILE = "vault.salt"
DB_FILE = "vault.db"

def get_or_create_salt():
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()
    else:
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        return salt

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

class MasterPasswordApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Güvenli Şifre Yöneticisi - Giriş")
        self.root.geometry("400x220")
        self.root.resizable(False, False)

        self.salt = get_or_create_salt()
        self.init_db()

        self.create_widgets()

    def init_db(self):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # Master şifre doğrulama tablosu ve şifre kasası tablosu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                id INTEGER PRIMARY KEY,
                master_hash TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vault (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT,
                username TEXT,
                password TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def create_widgets(self):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT master_hash FROM metadata WHERE id = 1")
        row = cursor.fetchone()
        conn.close()

        is_setup = row is None

        title_text = "İlk Kurulum: Ana Şifre Belirle" if is_setup else "Kilit Ekranı: Ana Şifre Girin"
        lbl_title = tk.Label(self.root, text=title_text, font=("Arial", 12, "bold"))
        lbl_title.pack(pady=15)

        lbl_pass = tk.Label(self.root, text="Master Şifre:")
        lbl_pass.pack(pady=5)

        self.ent_pass = tk.Entry(self.root, show="*", width=30, font=("Arial", 11))
        self.ent_pass.pack(pady=5)
        self.ent_pass.focus()

        btn_text = "Kasayı Oluştur ve Giriş Yap" if is_setup else "Kilidi Aç"
        btn_action = self.setup_master if is_setup else self.verify_master

        btn_submit = tk.Button(self.root, text=btn_text, command=btn_action, bg="#2e7d32", fg="white", font=("Arial", 10, "bold"), width=25, height=2)
        btn_submit.pack(pady=15)

    def setup_master(self):
        pwd = self.ent_pass.get()
        if len(pwd) < 6:
            messagebox.showerror("Hata", "Master şifre en az 6 karakter olmalıdır!")
            return

        key = derive_key(pwd, self.salt)
        # Basit bir doğrulama hash'i saklayalım
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO metadata (id, master_hash) VALUES (1, ?)", (key.decode(),))
        conn.commit()
        conn.close()

        messagebox.successful = messagebox.showinfo("Başarılı", "Master şifreniz başarıyla oluşturuldu!")
        self.open_main_vault(key)

    def verify_master(self):
        pwd = self.ent_pass.get()
        key = derive_key(pwd, self.salt)

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT master_hash FROM metadata WHERE id = 1")
        stored_hash = cursor.fetchone()[0]
        conn.close()

        if key.decode() == stored_hash:
            self.open_main_vault(key)
        else:
            messagebox.showerror("Hata", "Hatalı Master Şifre!")

    def open_main_vault(self, key):
        self.root.destroy()
        vault_root = tk.Tk()
        PasswordVaultApp(vault_root, key)
        vault_root.mainloop()


class PasswordVaultApp:
    def __init__(self, root, encryption_key):
        self.root = root
        self.root.title("Güvenli Şifre Yöneticisi - Kasa")
        self.root.geometry("700x500")
        self.root.resizable(False, False)

        self.cipher = Fernet(encryption_key)
        self.create_widgets()
        self.load_passwords()

    def create_widgets(self):
        title_label = tk.Label(self.root, text="Şifre Kasası", font=("Arial", 14, "bold"))
        title_label.pack(pady=10)

        # Tablo Alanı (Treeview)
        columns = ("ID", "Servis / Website", "Kullanıcı Adı", "Şifre")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=12)
        
        self.tree.heading("ID", text="ID")
        self.tree.heading("Servis / Website", text="Servis / Website")
        self.tree.heading("Kullanıcı Adı", text="Kullanıcı Adı")
        self.tree.heading("Şifre", text="Şifre")

        self.tree.column("ID", width=40, anchor="center")
        self.tree.column("Servis / Website", width=200)
        self.tree.column("Kullanıcı Adı", width=200)
        self.tree.column("Şifre", width=200)
        
        self.tree.pack(pady=10)

        # Kontrol Butonları Çerçevesi
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(fill="x", padx=20, pady=10)

        tk.Button(btn_frame, text="Yeni Şifre Ekle", command=self.add_password_window, bg="#1565c0", fg="white", font=("Arial", 10, "bold"), width=18, height=2).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Seçileni Panoya Kopyala", command=self.copy_password, bg="#2e7d32", fg="white", font=("Arial", 10, "bold"), width=22, height=2).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Seçileni Sil", command=self.delete_password, bg="#c62828", fg="white", font=("Arial", 10, "bold"), width=15, height=2).pack(side="right", padx=5)

    def load_passwords(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, service, username, password FROM vault")
        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            row_id, service, username, enc_pwd = row
            try:
                decrypted_pwd = self.cipher.decrypt(enc_pwd.encode()).decode()
            except Exception:
                decrypted_pwd = "[Şifre Çözülemedi]"

            # Güvenlik için arayüzde şifreyi yıldızlı gösterelim
            masked_pwd = "•" * len(decrypted_pwd)
            self.tree.insert("", "end", values=(row_id, service, username, masked_pwd), tags=(decrypted_pwd,))

    def add_password_window(self):
        add_win = tk.Toplevel(self.root)
        add_win.title("Yeni Şifre Ekle")
        add_win.geometry("350x280")
        add_win.resizable(False, False)

        tk.Label(add_win, text="Servis / Website Adı:").pack(anchor="w", padx=20, pady=(15, 0))
        ent_service = tk.Entry(add_win, width=35)
        ent_service.pack(padx=20, pady=5)

        tk.Label(add_win, text="Kullanıcı Adı / E-posta:").pack(anchor="w", padx=20)
        ent_user = tk.Entry(add_win, width=35)
        ent_user.pack(padx=20, pady=5)

        tk.Label(add_win, text="Şifre:").pack(anchor="w", padx=20)
        
        pass_frame = tk.Frame(add_win)
        pass_frame.pack(padx=20, pady=5, fill="x")

        ent_pass = tk.Entry(pass_frame, width=23)
        ent_pass.pack(side="left", padx=(0, 5))

        def generate_random():
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            pwd = "".join(secrets.choice(chars) for _ in range(12))
            ent_pass.delete(0, tk.END)
            ent_pass.insert(0, pwd)

        tk.Button(pass_frame, text="Üret", command=generate_random, width=8).pack(side="right")

        def save():
            srv = ent_service.get()
            usr = ent_user.get()
            pwd = ent_pass.get()

            if not srv or not usr or not pwd:
                messagebox.showerror("Hata", "Tüm alanları doldurmalısınız!")
                return

            enc_pwd = self.cipher.encrypt(pwd.encode()).decode()

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO vault (service, username, password) VALUES (?, ?, ?)", (srv, usr, enc_pwd))
            conn.commit()
            conn.close()

            messagebox.showinfo("Başarılı", "Şifre güvenle kaydedildi!")
            add_win.destroy()
            self.load_passwords()

        tk.Button(add_win, text="Kaydet", command=save, bg="#2e7d32", fg="white", font=("Arial", 10, "bold"), width=20).pack(pady=15)

    def copy_password(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Uyarı", "Lütfen listeden bir kayıt seçin!")
            return

        item = self.tree.item(selected_item)
        # Gerçek şifreyi tree tag'inde saklamıştık
        tags = item.get("tags")
        if tags:
            real_password = tags[0]
            self.root.clipboard_clear()
            self.root.clipboard_append(real_password)
            messagebox.showinfo("Başarılı", "Şifre panoya kopyalandı!")

    def delete_password(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Uyarı", "Lütfen silinecek kaydı seçin!")
            return

        item = self.tree.item(selected_item)
        row_id = item["values"][0]

        if messagebox.askyesno("Onay", "Bu kaydı silmek istediğinize emin misiniz?"):
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM vault WHERE id = ?", (row_id,))
            conn.commit()
            conn.close()
            self.load_passwords()
            messagebox.showinfo("Başarılı", "Kayıt silindi.")

if __name__ == "__main__":
    root = tk.Tk()
    app = MasterPasswordApp(root)
    root.mainloop()
