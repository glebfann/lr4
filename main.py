# Стандартные библиотеки Python
import io
import os
import sys
import json
import shutil
import platform
import re
from sys import exit

# Библиотеки для работы с Windows
import winreg
import wmi

# Криптографические библиотеки
import hashlib
from Crypto.Cipher import AES
from Crypto.Hash import MD2
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Библиотеки для GUI
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog

class Installer:
  def __init__(self):
      self.root = tk.Tk()
      self.root.withdraw()
      self.system_info = {}
      self.private_key = None
      self.public_key = None

  def generate_keys(self):
      private_key = rsa.generate_private_key(
          public_exponent=65537,
          key_size=2048
      )
      public_key = private_key.public_key()

      with open("private_key.pem", "wb") as f:
          f.write(private_key.private_bytes(
              encoding=serialization.Encoding.PEM,
              format=serialization.PrivateFormat.PKCS8,
              encryption_algorithm=serialization.NoEncryption()
          ))

      with open("public_key.pem", "wb") as f:
          f.write(public_key.public_bytes(
              encoding=serialization.Encoding.PEM,
              format=serialization.PublicFormat.SubjectPublicKeyInfo
          ))

      self.private_key = private_key
      self.public_key = public_key

  def collect_system_info(self):
      c = wmi.WMI()

      self.system_info = {
          'username': os.getenv('USERNAME'),
          'computer_name': platform.node(),
          'windows_path': os.getenv('WINDIR'),
          'system_path': os.getenv('SYSTEMROOT'),
          'keyboard_info': '',
          'screen_height': self.root.winfo_screenheight(),
          'ram_size': 0,
          'disk_serial': ''
      }

      for item in c.Win32_Keyboard():
          self.system_info['keyboard_info'] = f"{item.Description} ({item.NumberOfFunctionKeys} function keys)"

      for item in c.Win32_ComputerSystem():
          self.system_info['ram_size'] = item.TotalPhysicalMemory

      for item in c.Win32_DiskDrive():
          self.system_info['disk_serial'] = item.SerialNumber
          break

  def hash_system_info(self):
      info_string = ''.join(str(value) for value in self.system_info.values())
      return hashlib.sha256(info_string.encode()).digest()

  def sign_system_info(self, hashed_info):
      signature = self.private_key.sign(
          hashed_info,
          padding.PSS(
              mgf=padding.MGF1(hashes.SHA256()),
              salt_length=padding.PSS.MAX_LENGTH
          ),
          hashes.SHA256()
      )
      return signature

  def write_to_registry(self, signature):
      try:
          key_path = r"Software\Fandeev"
          key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
          winreg.SetValueEx(key, "Signature", 0, winreg.REG_BINARY, signature)
          winreg.CloseKey(key)
          return True
      except Exception as e:
          print(f"Ошибка при записи в реестр: {e}")
          return False

  def install(self):
      install_dir = filedialog.askdirectory(title="Выберите директорию для установки")
      if not install_dir:
          messagebox.showerror("Ошибка", "Директория не выбрана")
          return False

      try:
          self.generate_keys()
          program_path = os.path.join(install_dir, "program.py")
          shutil.copy2(__file__, program_path)  # Копируем текущий файл
          shutil.copy2("public_key.pem", os.path.join(install_dir, "public_key.pem"))

          self.collect_system_info()
          hashed_info = self.hash_system_info()
          signature = self.sign_system_info(hashed_info)

          if not self.write_to_registry(signature):
              messagebox.showerror("Ошибка", "Не удалось записать данные в реестр")
              return False

          messagebox.showinfo("Успех", "Установка завершена успешно")
          return True

      except Exception as e:
          messagebox.showerror("Ошибка", f"Произошла ошибка при установке: {str(e)}")
          return False

def verify_installation():
  try:
      registry_name = simpledialog.askstring("Верификация", "Введите имя раздела реестра (фамилию):")
      if not registry_name:
          messagebox.showerror("Ошибка", "Имя раздела не указано")
          return False

      c = wmi.WMI()
      system_info = {
          'username': os.getenv('USERNAME'),
          'computer_name': platform.node(),
          'windows_path': os.getenv('WINDIR'),
          'system_path': os.getenv('SYSTEMROOT'),
          'keyboard_info': '',
          'screen_height': root.winfo_screenheight(),
          'ram_size': 0,
          'disk_serial': ''
      }

      for item in c.Win32_Keyboard():
          system_info['keyboard_info'] = f"{item.Description} ({item.NumberOfFunctionKeys} function keys)"

      for item in c.Win32_ComputerSystem():
          system_info['ram_size'] = item.TotalPhysicalMemory

      for item in c.Win32_DiskDrive():
          system_info['disk_serial'] = item.SerialNumber
          break

      info_string = ''.join(str(value) for value in system_info.values())
      current_hash = hashlib.sha256(info_string.encode()).digest()

      key_path = f"Software\\{registry_name}"
      key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
      signature = winreg.QueryValueEx(key, "Signature")[0]
      winreg.CloseKey(key)

      with open("public_key.pem", "rb") as key_file:
          public_key = serialization.load_pem_public_key(key_file.read())

      try:
          public_key.verify(
              signature,
              current_hash,
              padding.PSS(
                  mgf=padding.MGF1(hashes.SHA256()),
                  salt_length=padding.PSS.MAX_LENGTH
              ),
              hashes.SHA256()
          )
          return True
      except Exception:
          return False

  except Exception as e:
      messagebox.showerror("Ошибка", f"Ошибка верификации: {str(e)}")
      return False

def get_key_from_passphrase(passphrase):
    hash_obj = MD2.new(passphrase.encode('utf-8'))
    return hash_obj.digest()

def encrypt_file(input_data, output_filename, passphrase):
    data = input_data.getvalue()
    key = get_key_from_passphrase(passphrase)

    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)

    with open(output_filename, 'wb') as file:
        file.write(encrypted_data)

def decrypt_file_in_memory(input_filename, passphrase):
    with open(input_filename, 'rb') as file:
        encrypted_data = file.read()

    key = get_key_from_passphrase(passphrase)

    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded_data = cipher.decrypt(encrypted_data)
    try:
        decrypted_data = unpad(decrypted_padded_data, AES.block_size).decode('utf-8')
    except (ValueError, KeyError):
        messagebox.showerror("Ошибка", "Неверная парольная фраза.")
        exit(1)

    try:
        loaded_data = json.loads(decrypted_data)
    except json.JSONDecodeError as e:
        print(f"Ошибка декодирования JSON: {e}")
        raise

    json_data_in_memory = io.StringIO()
    json.dump(loaded_data, json_data_in_memory, ensure_ascii=False)
    json_data_in_memory.seek(0)

    return json_data_in_memory

class UserManager:
    def __init__(self, encrypted_filename='users_encrypted.dat'):
        self.encrypted_filename = encrypted_filename
        self.users = {}
        self.decrypted_file= io.StringIO()

    def load_users(self, passphrase):
        try:
            self.decrypted_file = decrypt_file_in_memory(self.encrypted_filename, passphrase)
            self.users = json.loads(self.decrypted_file.getvalue())
        except (FileNotFoundError, ValueError):
            messagebox.showerror("Ошибка", "Файл не найден.")
            exit(1)

    def save_users(self, passphrase):
        self.decrypted_file.seek(0)
        self.decrypted_file.truncate(0)
        json.dump(self.users, self.decrypted_file, ensure_ascii=False)
        self.decrypted_file.seek(0)
        encrypt_file(self.decrypted_file, self.encrypted_filename, passphrase)


    def validate_password_strength(self, password):
        if not re.search(r'[A-ZА-Я]', password):
            return False, "Пароль должен содержать хотя бы одну заглавную букву"
        if not re.search(r'[a-zа-я]', password):
            return False, "Пароль должен содержать хотя бы одну строчную букву"
        if not re.search(r"[+=\-*/]", password):
            return False, "Пароль должен содержать хотя бы один арифметический оператор"
        if not re.search(r'[.,;!?]', password):
            return False, "Пароль должен содержать хотя бы один знак препинания"
        return True, ""

    def add_user(self, username, passphrase):
        if username.lower() in [user.lower() for user in self.users]:
            return False, "Пользователь уже существует"
        self.users[username] = {'password': '', 'blocked': False, 'restrictions': False}
        self.save_users(passphrase)
        return True, ""

    def change_password(self, username, old_password, new_password, passphrase):
        if self.users[username]['password'] != old_password:
            return False, "Неверный старый пароль"
        if self.users[username]['restrictions']:
            valid, message = self.validate_password_strength(new_password)
            if not valid:
                return False, message
        self.users[username]['password'] = new_password
        self.save_users(passphrase)
        return True, ""

    def block_user(self, username, passphrase):
        if username in self.users:
            self.users[username]['blocked'] = not(self.users[username]['blocked'])
            self.save_users(passphrase)
            return True, self.users[username]['blocked']
        return False, "Пользователь не найден"

    def toggle_restrictions(self, username, passphrase):
        if username in self.users:
            self.users[username]['restrictions'] = not self.users[username]['restrictions']
            self.save_users(passphrase)
            return True, ""
        return False, "Пользователь не найден"

class AppInterface:
    def __init__(self, root):
        self.root = root
        self.root.title("Приложение")
        self.manager = UserManager()
        self.attempts = 0
        self.passphrase = ""

        self.passphrase_frame = tk.Frame(self.root)
        self.passphrase_frame.pack(pady=20)

        tk.Label(self.passphrase_frame, text="Парольная фраза:").grid(row=0, column=0, padx=5, pady=5)
        self.passphrase_entry = tk.Entry(self.passphrase_frame, show='*')
        self.passphrase_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Button(self.passphrase_frame, text="Подтвердить", command=self.submit_passphrase).grid(row=1, column=0, columnspan=2,
                                                                                        pady=10)
    def submit_passphrase(self):
        self.passphrase = self.passphrase_entry.get()
        if not self.passphrase:
            messagebox.showerror("Ошибка", "Парольная фраза не может быть пустой")
            return
        try:
            self.manager.load_users(self.passphrase)
            self.passphrase_frame.destroy()
            self.login_init()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def login_init(self):
        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack(pady=20)

        tk.Label(self.login_frame, text="Имя пользователя:").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = tk.Entry(self.login_frame, font=("Arial", 12))
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(self.login_frame, text="Пароль:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(self.login_frame, show='*', font=("Arial", 12))
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        self.login_button = tk.Button(self.login_frame, text="Войти", command=self.login)
        self.login_button.grid(row=2, column=0, columnspan=2, pady=10)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        username_lower = username.lower()
        if username_lower not in [user.lower() for user in self.manager.users]:
            messagebox.showerror("Ошибка", "Пользователь не найден")
            return

        actual_username = [user for user in self.manager.users if user.lower() == username_lower][0]

        if self.manager.users[actual_username]['blocked']:
            messagebox.showerror("Ошибка", "Пользователь заблокирован")
            return

        if self.manager.users[actual_username]['password'] == "":
            self.first_time_login(actual_username)
        elif self.manager.users[actual_username]['password'] == password:
            self.open_main_menu(actual_username)
        else:
            self.attempts += 1
            if self.attempts >= 3:
                messagebox.showerror("Ошибка", "Слишком много неверных попыток")
                self.root.quit()
            else:
                messagebox.showerror("Ошибка", "Неверный пароль")

    def first_time_login(self, username):
        if not self.password_entry.get():
            new_password = simpledialog.askstring("Первый вход", "Введите новый пароль:", show='*')
            if new_password:
                confirm_password = simpledialog.askstring("Подтверждение пароля", "Подтвердите пароль:", show='*')
                if confirm_password:
                    if new_password != confirm_password:
                        messagebox.showerror("Ошибка", "Пароли не совпадают")
                        return

                    if self.manager.users[username]['restrictions']:
                        valid, message = self.manager.validate_password_strength(new_password)
                        if not valid:
                            messagebox.showerror("Ошибка", message)
                            return

                    self.manager.users[username]['password'] = new_password
                    self.manager.save_users(self.passphrase)
                    self.open_main_menu(username)
        else:
            messagebox.showerror("Ошибка", "Вы входите в систему в первый раз, оставьте строку пароля пустой")

    def show_about(self):
        messagebox.showinfo("О программе",
                            "Автор: Фандеев Глеб \nИндивидуальное задание 19\nТип симметричного шифрования: блочный, Используемый алгоритм хеширования: MD2.")

    def open_main_menu(self, username):
        self.login_frame.destroy()

        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)

        help_menu = tk.Menu(self.menu_bar, tearoff=0)
        help_menu.add_command(label="О программе", command=self.show_about)

        if username == 'admin':
            admin_menu = tk.Menu(self.menu_bar, tearoff=0)
            admin_menu.add_command(label="Изменить пароль", command=self.change_admin_password)
            admin_menu.add_command(label="Управление пользователями", command=self.manage_users)
            admin_menu.add_separator()
            admin_menu.add_command(label="Выход", command=self.root.quit)
            self.menu_bar.add_cascade(label="Администратор", menu=admin_menu)
            self.menu_bar.add_cascade(label="Помощь", menu=help_menu)
        else:
            user_menu = tk.Menu(self.menu_bar, tearoff=0)
            user_menu.add_command(label="Изменить пароль", command=lambda: self.change_user_password(username))
            user_menu.add_separator()
            user_menu.add_command(label="Выход", command=self.root.quit)
            self.menu_bar.add_cascade(label="Пользователь", menu=user_menu)
            self.menu_bar.add_cascade(label="Помощь", menu=help_menu)

    def change_admin_password(self, username):
        old_password = simpledialog.askstring("Старый пароль", "Введите старый пароль:", show='*')
        if old_password:
            new_password = simpledialog.askstring("Новый пароль", "Введите новый пароль:", show='*')
            if new_password:
                confirm_password = simpledialog.askstring("Подтверждение пароля", "Подтвердите пароль:", show='*')
                if confirm_password:
                    if new_password != confirm_password:
                        messagebox.showerror("Ошибка", "Пароли не совпадают")
                        return

                    success, message = self.manager.change_password(username, old_password, new_password, self.passphrase)
                    if success:
                        messagebox.showinfo("Успех", "Пароль изменен")
                    else:
                        messagebox.showerror("Ошибка", message)

    def manage_users(self):
        manage_window = tk.Toplevel(self.root)
        manage_window.title("Управление пользователями")

        self.current_user_index = 0

        def update_user_info():
            if not self.manager.users:
                return

            username = list(self.manager.users.keys())[self.current_user_index]
            user_info = self.manager.users[username]

            user_info_label.config(
                text=f"Username: {username}\nBlocked: {user_info['blocked']}\nPassword Restrictions: {user_info['restrictions']}")

        def next_user():
            self.current_user_index = (self.current_user_index + 1) % len(self.manager.users)
            update_user_info()

        def prev_user():
            self.current_user_index = (self.current_user_index - 1) % len(self.manager.users)
            update_user_info()

        def add_user():
            username = new_user_entry.get().strip()
            if username:
                success, message = self.manager.add_user(username, self.passphrase)
                if success:
                    messagebox.showinfo("Успех", f"User '{username}' успешно доавблен")
                    update_user_info()
                else:
                    messagebox.showerror("Ошибка", message)

        def block_user():
            username = list(self.manager.users.keys())[self.current_user_index]
            success, flag = self.manager.block_user(username, self.passphrase)
            if success:
                if flag:
                    messagebox.showinfo("Успех", f"Пользователь '{username}' был заблокирован ")
                else:
                    messagebox.showinfo("Успех", f"Пользователь '{username}' ыл разблокирован")
                update_user_info()
            else:
                messagebox.showerror("Ошибка", "")

        def toggle_restrictions():
            username = list(self.manager.users.keys())[self.current_user_index]
            success, message = self.manager.toggle_restrictions(username, self.passphrase)
            if success:
                messagebox.showinfo("Ошибка",
                                    f"Ограничения '{username}' были {'включены' if self.manager.users[username]['restrictions'] else 'отключены'}")
                update_user_info()
            else:
                messagebox.showerror("Ошибка", message)

        user_info_label = tk.Label(manage_window, text="")
        user_info_label.grid(row=0, column=0, columnspan=2, padx=5, pady=5)

        tk.Button(manage_window, text="Предыдущий пользователь", command=prev_user).grid(row=1, column=0, padx=5,
                                                                                         pady=5)
        tk.Button(manage_window, text="Следующий пользователь", command=next_user).grid(row=1, column=1, padx=5, pady=5)

        tk.Label(manage_window, text="Введите имя нового пользователя:").grid(row=2, column=0, padx=5, pady=5)
        new_user_entry = tk.Entry(manage_window)
        new_user_entry.grid(row=2, column=1, padx=5, pady=5)

        tk.Button(manage_window, text="Добавить пользователя", command=add_user).grid(row=3, column=0, columnspan=2,
                                                                                      pady=5)

        tk.Button(manage_window, text="Заблокировать", command=block_user).grid(row=4, column=0, padx=5, pady=5)
        tk.Button(manage_window, text="Включить ограничения", command=toggle_restrictions).grid(row=4, column=1,
                                                                                                padx=5, pady=5)

        update_user_info()

    def change_user_password(self, username):
        old_password = simpledialog.askstring("Старый пароль", "Введите старый пароль:", show='*')
        if old_password:
            new_password = simpledialog.askstring("Новый пароль", "Введите новй пароль:", show='*')
            if new_password:
                confirm_password = simpledialog.askstring("Подтверждение пароля", "Подтвердите пароль:", show='*')
                if confirm_password:
                    if new_password != confirm_password:
                        messagebox.showerror("Ошибка", "Пароли не совпадают")
                        return

                    success, message = self.manager.change_password(username, old_password, new_password,
                                                                    self.passphrase)
                    if success:
                        messagebox.showinfo("Успех", "Пароль изменен")
                    else:
                        messagebox.showerror("Ошибка", message)

def on_closing():
    if messagebox.askokcancel("Выход", "Вы хотите выйти?"):
        root.destroy()


def on_opening():
    if os.path.exists('users_encrypted.dat'):
        return
    else:
        passphrase = simpledialog.askstring("Введите пароль", "Введите пароль для шифрования файла:", show='*')
        if not passphrase:
            messagebox.showwarning("Отменено", "Операция отменена, файл не будет создан.")
            exit(0)
            return

        initial_users = {'admin': {'password': '', 'blocked': False, 'restrictions': False}}

        json_data_in_memory = io.StringIO()
        json.dump(initial_users, json_data_in_memory, ensure_ascii=False)
        json_data_in_memory.seek(0)

        encrypt_file(json_data_in_memory, 'users_encrypted.dat', passphrase)
        messagebox.showinfo("Успех", f"Файл 'users_encrypted.dat' успешно создан и зашифрован.")

if __name__ == "__main__":
  if len(sys.argv) > 1 and sys.argv[1] == "--install":
      installer = Installer()
      installer.install()
  else:
      root = tk.Tk()
      if not verify_installation():
          messagebox.showerror("Ошибка", "Проверка подлинности не пройдена")
          root.quit()
      else:
          app = AppInterface(root)
          on_opening()
          root.protocol("WM_DELETE_WINDOW", on_closing)
          root.mainloop()
