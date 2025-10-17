import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QPushButton, QLineEdit,
    QFileDialog, QTextEdit, QMessageBox
)
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtCore import Qt, QSize
import os
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
def password_key(password: str, salt: bytes, iterations: int = 390_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)
def encrypt_text(plain_text: str, password: str) -> bytes:
    salt = os.urandom(16)
    key = password_key(password, salt)
    f = Fernet(key)
    token = f.encrypt(plain_text.encode())
    return salt + token
def decrypt_text(encrypted_blob: bytes, password: str) -> str:
    if len(encrypted_blob) < 17:
        raise ValueError("Invalid encrypted blob")
    salt = encrypted_blob[:16]
    token = encrypted_blob[16:]
    key = password_key(password, salt)
    f = Fernet(key)
    plain = f.decrypt(token)
    return plain.decode()
class password(QMainWindow):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("Mo-crypt - Set Password")
        self.setFixedSize(600, 300)
        try:
            self.setWindowIcon(QIcon("mo-crypt icon.png"))
        except:
            pass
        self.buttonpas1 = QPushButton("back", self)
        self.buttonpas2 = QPushButton("confirm", self)
        self.buttonpas1.setGeometry(8, 240, 290, 50)
        self.buttonpas2.setGeometry(302, 240, 290, 50)
        self.buttonpas1.setFont(QFont("Arial", 10))
        self.buttonpas2.setFont(QFont("Arial", 10))
        self.passline1 = QLineEdit(self)
        self.passline2 = QLineEdit(self)
        self.passline1.setPlaceholderText("the password")
        self.passline2.setPlaceholderText("repeat the password")
        self.passline1.setGeometry(10, 80, 580, 40)
        self.passline2.setGeometry(10, 160, 580, 40)
        self.labeltext1 = QLabel("enter password at least four digits:", self)
        self.labeltext1.setGeometry(10, 0, 580, 60)
        self.labeltext1.setFont(QFont("Arial", 10))
        self.passline1.setEchoMode(QLineEdit.Password)
        self.passline2.setEchoMode(QLineEdit.Password)
        self.worningalart = QLabel("** the password should be large than four digits.", self)
        self.worningalart2 = QLabel("** the password not same", self)
        for lbl in [self.worningalart, self.worningalart2]:
            lbl.setGeometry(10, 210, 580, 40)
            lbl.setStyleSheet("font-family:Arial; font-size:12px; color:red;")
            lbl.hide()
        self.buttonpas1.clicked.connect(self.go_back2)
        self.buttonpas2.clicked.connect(self.save_password)
    def save_password(self):
        self.password_enter = self.passline1.text().strip()
        if len(self.password_enter) >= 4:
            if self.password_enter == self.passline2.text().strip():
                self.password_save_copy = self.password_enter
                self.worningalart.hide()
                self.worningalart2.hide()
                try:
                    self.main_window.createbut.setText("Password saved")
                    self.main_window.createbut.setDisabled(True)
                    self.main_window.encrypt_button.setDisabled(False)
                except Exception:
                    pass
                self.close()
            else:
                self.worningalart2.show()
        else:
            self.worningalart.show()
    def go_back2(self):
        self.close()
    def keyPressEvent(self, event):
        # Allow Esc to clear the fields
        if event.key() == Qt.Key_Escape:
            self.passline1.clear()
            self.passline2.clear()
class password_submit(QMainWindow):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setFixedSize(500, 250)
        try:
            self.setWindowIcon(QIcon("mo-crypt icon.png"))
        except:
            pass
        self.setWindowTitle("Mo-crypt")
        self.tech1m = QLineEdit(self)
        self.tech1m.setGeometry(10, 85, 480, 60)
        self.tech1m.setPlaceholderText("the password")
        self.tech1m.setEchoMode(QLineEdit.Password)
        self.labelenterpass = QLabel("please, enter the password:", self)
        self.labelenterpass.setGeometry(10, 0, 500, 70)
        self.labelenterpass.setFont(QFont("Arial", 10))
        self.backdecryptwindowpass = QPushButton("back", self)
        self.backdecryptwindowpass.setGeometry(10, 180, 235, 60)
        self.backdecryptwindowpass.setFont(QFont("Arial", 20))
        self.backdecryptwindowpass.clicked.connect(self.go_back3)
        self.gowindowpass = QPushButton("confirm", self)
        self.gowindowpass.setGeometry(255, 180, 235, 60)
        self.gowindowpass.setFont(QFont("Arial", 20))
        self.gowindowpass.clicked.connect(self.confirmbut1)
        self.alartpassw = QLabel("** the password should be longer than four digits.", self)
        self.alartpassw.setGeometry(10, 160, 480, 60)
        self.alartpassw.setStyleSheet("font-size:12px; font-family:Arial; color:red;")
        self.alartpassw.hide()
    def confirmbut1(self):
        self.passwordtodecrypt = self.tech1m.text().strip()
        if len(self.passwordtodecrypt) >= 4:
            self.password_save_copy = self.passwordtodecrypt
            self.alartpassw.hide()
            try:
                self.main_window.createbut1.setDisabled(True)
                self.main_window.createbut1.setText("password saved")
                self.main_window.decrypt_button.setDisabled(False)
            except Exception:
                pass
            self.close()
        else:
            self.alartpassw.show()
    def go_back3(self):
        self.close()
    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.tech1m.clear()
class Encrypt_window(QMainWindow):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("Mo-crypt")
        self.setFixedSize(600, 750)
        try:
            self.setWindowIcon(QIcon("mo-crypt icon.png"))
        except:
            pass
        self.but3 = QPushButton("back", self)
        self.but3.setGeometry(380, 680, 100, 60)
        self.but3.setFont(QFont("Arial", 10))
        self.but3.clicked.connect(self.go_back)
        self.lab3 = QLabel("please, enter the type of data do you want to encrypt:", self)
        self.but4 = QPushButton("submit", self)
        self.in_text1 = QLineEdit(self)
        self.en_initUI()
    def en_initUI(self):
        self.lab3.setGeometry(0, 0, 600, 50)
        self.lab3.setStyleSheet("font-size:20px; font-family:Arial;")
        self.in_text1.setGeometry(10, 50, 450, 40)
        self.in_text1.setStyleSheet("font-size:20px; font-family:Arial;")
        self.in_text1.setPlaceholderText("file or text")
        self.but4.setGeometry(470, 50, 120, 40)
        self.but4.setStyleSheet("font-size:20px; font-family:Arial;")
        self.but4.clicked.connect(self.on_click)
        self.lab4 = QLabel("** please, Try again.", self)
        self.lab4.setGeometry(10, 92, 580, 20)
        self.lab4.setStyleSheet("font-size:15px; color:red; font-family:Arial;")
        self.lab4.hide()
        self.lab7 = QLabel("please, choose the file that you needs:", self)
        self.lab7.setGeometry(0, 110, 360, 30)
        self.lab7.setStyleSheet("font-size:20px; font-family:Arial;")
        self.but7 = QPushButton("browse the files", self)
        self.but7.setGeometry(370, 110, 220, 40)
        self.but7.setStyleSheet("font-size:20px; font-family:Arial;")
        self.lab7.hide()
        self.but7.hide()
        self.but7.clicked.connect(self.open_file_dialog1)
        self.text1 = QTextEdit(self)
        self.text1.setGeometry(10, 170, 580, 300)
        self.text1.setFont(QFont("Arial", 10))
        self.text1.textChanged.connect(self.max_word)
        self.text1.hide()
        self.labt = QLabel("enter the text that's need to encrypt.-less or equal 3000 words-", self)
        self.labt.setGeometry(10, 140, 600, 30)
        self.labt.setFont(QFont("Arial", 10))
        self.labt.hide()
        self.butst = QPushButton("save the text", self)
        self.butst.setGeometry(10, 480, 580, 50)
        self.butst.setFont(QFont("Arial", 15))
        self.butst.setDisabled(True)
        self.text1.textChanged.connect(self.togglesbut)
        self.butst.hide()
        self.butst.clicked.connect(self.save_text)
        self.createbut = QPushButton("create password", self)
        self.createbut.setGeometry(10, 535, 580, 50)
        self.createbut.setFont(QFont("Arial", 15))
        self.createbut.hide()
        self.createbut.clicked.connect(self.winpa)
        self.createbut.setDisabled(True)
        self.encrypt_button = QPushButton("encrypt", self)
        self.encrypt_button.setGeometry(490, 680, 100, 60)
        self.encrypt_button.setFont(QFont("Arial", 10))
        self.encrypt_button.setDisabled(True)
        self.encrypt_button.clicked.connect(self.encrypt_action)
    def is_encrypted_file(self, filepath):
        try:
            if not os.path.isfile(filepath):
                return False
            with open(filepath, "rb") as f:
                data = f.read(64)
                if len(data) >= 22:
                    token_start = data[16:22]
                    if token_start.startswith(b"gAAAAA"):
                        return True
            if filepath.lower().endswith(".bin"):
                with open(filepath, "rb") as f:
                    data = f.read(1024)
                    if len(data) >= 22 and data[16:22].startswith(b"gAAAAA"):
                        return True
                return False
            return False
        except Exception:
            return False
    def winpa(self):
        self.paswo = password(self)
        self.paswo.show()
    def encrypt_action(self):
        try:
            password_value = getattr(getattr(self, "paswo", None), "password_save_copy", None)
            if not password_value:
                QMessageBox.warning(self, "Error", "No password found. Please create and confirm a password first.")
                return
            if hasattr(self, "e_text") and self.e_text.strip():
                encrypted_data = encrypt_text(self.e_text, password_value)
                save_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted Text", "", "Encrypted Files (*.bin);;All Files (*)")
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(encrypted_data)
                    QMessageBox.information(self, "Done", "Text encrypted successfully ")
                return
            if hasattr(self, "s_file") and os.path.isfile(self.s_file):
                if self.is_encrypted_file(self.s_file):
                    QMessageBox.warning(self, "Error", "This file is already encrypted ")
                    return
                with open(self.s_file, "r", encoding="utf-8", errors="ignore") as file_data:
                    content = file_data.read()
                encrypted_data = encrypt_text(content, password_value)
                save_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File", "", "Encrypted Files (*.bin);;All Files (*)")
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(encrypted_data)
                    QMessageBox.information(self, "Done", "File encrypted successfully ")
                return
            QMessageBox.warning(self, "Error", "No data found to encrypt.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed:\n{str(e)}")
    def togglesbut(self):
        text = self.text1.toPlainText().strip()
        self.butst.setDisabled(len(text) == 0)
    def max_word(self):
        text = self.text1.toPlainText()
        words = text.split()
        if len(words) > 3000:
            new_text = " ".join(words[:3000])
            self.text1.blockSignals(True)
            self.text1.setPlainText(new_text)
            cursor = self.text1.textCursor()
            cursor.movePosition(cursor.End)
            self.text1.setTextCursor(cursor)
            self.text1.blockSignals(False)
    def open_file_dialog1(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Choose file", "", "All Files (*.*)")
        if file_path:
            self.s_file = file_path
            self.but7.setDisabled(True)
            self.createbut.setDisabled(False)
    def save_text(self):
        self.e_text = self.text1.toPlainText()
        self.butst.setText("the text saved")
        self.butst.setDisabled(True)
        self.createbut.setDisabled(False)
    def on_click(self):
        type_of_data = self.in_text1.text().strip()
        if type_of_data == "file":
            self.lab4.hide()
            self.lab7.show()
            self.but7.show()
            self.text1.hide()
            self.labt.hide()
            self.butst.hide()
            self.createbut.show()
        elif type_of_data == "text":
            self.lab4.hide()
            self.lab7.hide()
            self.but7.hide()
            self.text1.show()
            self.labt.show()
            self.butst.show()
            self.createbut.show()
        else:
            self.lab4.show()
    def go_back(self):
        self.close()
        self.main_window.show()
    def keyPressEvent(self, event):
        if event.modifiers() == Qt.ControlModifier and event.key() == Qt.Key_E:
            if not self.encrypt_button.isEnabled():
                QMessageBox.information(self, "Info", "You must create password first.")
            else:
                self.encrypt_action()
        elif event.modifiers() == Qt.ControlModifier and event.key() == Qt.Key_O:
            self.open_file_dialog1()
        elif event.key() == Qt.Key_Escape:
            if hasattr(self, "paswo"):
                try:
                    self.paswo.passline1.clear()
                    self.paswo.passline2.clear()
                except Exception:
                    pass
class Decrypt_window(QMainWindow):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("Mo-crypt")
        self.setFixedSize(600, 750)
        try:
            self.setWindowIcon(QIcon("mo-crypt icon.png"))
        except:
            pass
        self.but5 = QPushButton("back", self)
        self.but5.setGeometry(380, 680, 100, 60)
        self.but5.clicked.connect(self.go_back1)
        self.but5.setFont(QFont("Arial", 10))
        self.lab20 = QLabel("please, enter what type of data do you want to decrypt:", self)
        self.lab20.setGeometry(0, 0, 600, 50)
        self.lab20.setStyleSheet("font-size:20px; font-family:Arial;")
        self.in_text2 = QLineEdit(self)
        self.in_text2.setGeometry(10, 50, 450, 40)
        self.in_text2.setPlaceholderText("file or text")
        self.in_text2.setStyleSheet("font-size:20px; font-family:Arial;")
        self.but6 = QPushButton("submit", self)
        self.but6.setGeometry(470, 50, 120, 40)
        self.but6.setStyleSheet("font-size:20px; font-family:Arial;")
        self.but6.clicked.connect(self.on_click1)
        self.lab6 = QLabel("** please, Try again.", self)
        self.lab6.setGeometry(10, 92, 580, 20)
        self.lab6.setStyleSheet("font-size:15px; color:red; font-family:Arial;")
        self.lab6.hide()
        self.lab8 = QLabel("please, choose the file that you needs:", self)
        self.lab8.setGeometry(0, 110, 360, 30)
        self.lab8.setStyleSheet("font-size:20px; font-family:Arial;")
        self.but8 = QPushButton("browse the files", self)
        self.but8.setGeometry(370, 110, 220, 40)
        self.but8.setStyleSheet("font-size:20px; font-family:Arial;")
        self.lab8.hide()
        self.but8.hide()
        self.but8.clicked.connect(self.open_file_dialog2)
        self.text2 = QTextEdit(self)
        self.text2.setGeometry(10, 170, 580, 300)
        self.text2.setFont(QFont("Arial", 10))
        self.text2.textChanged.connect(self.max_word1)
        self.text2.hide()
        self.labt1 = QLabel("enter the text that's need to decrypt.-less or equal 3000 words-", self)
        self.labt1.setGeometry(10, 140, 600, 30)
        self.labt1.setFont(QFont("Arial", 10))
        self.labt1.hide()
        self.labstext1 = QPushButton("save the text", self)
        self.labstext1.setGeometry(10, 480, 580, 60)
        self.labstext1.setFont(QFont("Arial", 20))
        self.labstext1.hide()
        self.labstext1.setDisabled(True)
        self.text2.textChanged.connect(self.togglesbut1)
        self.labstext1.clicked.connect(self.save_text1)
        self.createbut1 = QPushButton("password window", self)
        self.createbut1.setGeometry(10, 545, 580, 60)
        self.createbut1.setFont(QFont("Arial", 20))
        self.createbut1.hide()
        self.createbut1.clicked.connect(self.password_window_show)
        self.createbut1.setDisabled(True)
        self.decrypt_button = QPushButton("decrypt", self)
        self.decrypt_button.setGeometry(490, 680, 100, 60)
        self.decrypt_button.setFont(QFont("Arial", 10))
        self.decrypt_button.setDisabled(True)
        self.decrypt_button.clicked.connect(self.decrypt_action)
    def is_encrypted_file(self, filepath):
        try:
            if not os.path.isfile(filepath):
                return False
            with open(filepath, "rb") as f:
                data = f.read(64)
                if len(data) >= 22 and data[16:22].startswith(b"gAAAAA"):
                    return True
            return False
        except Exception:
            return False
    def password_window_show(self):
        self.paswo1 = password_submit(self)
        self.paswo1.show()
    def save_text1(self):
        self.dm_text = self.text2.toPlainText()
        self.labstext1.setText("the text saved")
        self.labstext1.setDisabled(True)
        self.createbut1.setDisabled(False)
    def togglesbut1(self):
        text3 = self.text2.toPlainText()
        self.labstext1.setDisabled(len(text3.strip()) == 0)
    def max_word1(self):
        text2 = self.text2.toPlainText()
        words2 = text2.split()
        if len(words2) > 3000:
            new_text2 = " ".join(words2[:3000])
            self.text2.blockSignals(True)
            self.text2.setPlainText(new_text2)
            cursor2 = self.text2.textCursor()
            cursor2.movePosition(cursor2.End)
            self.text2.setTextCursor(cursor2)
            self.text2.blockSignals(False)
    def open_file_dialog2(self):
        file_path1, _ = QFileDialog.getOpenFileName(self, "Choose file", "", "All Files (*.*)")
        if file_path1:
            self.save_file300 = file_path1
            self.but8.setDisabled(True)
            self.createbut1.setDisabled(False)
    def on_click1(self):
        type_of_data1 = self.in_text2.text().strip()
        if type_of_data1 == "file":
            self.lab6.hide()
            self.lab8.show()
            self.but8.show()
            self.labt1.hide()
            self.text2.hide()
            self.labstext1.hide()
            self.createbut1.show()
        elif type_of_data1 == "text":
            self.lab6.hide()
            self.lab8.hide()
            self.but8.hide()
            self.labt1.show()
            self.text2.show()
            self.labstext1.show()
            self.createbut1.show()
        else:
            self.lab6.show()
            self.lab8.hide()
            self.but8.hide()
            self.labt1.hide()
            self.text2.hide()
            self.labstext1.hide()
            self.createbut1.hide()
    def decrypt_action(self):
        try:
            password_value = getattr(getattr(self, "paswo1", None), "password_save_copy", None)
            if not password_value:
                QMessageBox.warning(self, "Error", "No password entered. Please enter password first.")
                return
            if hasattr(self, "dm_text") and self.dm_text.strip():
                raw = self.dm_text.strip()
                decrypted_text = None
                try:
                    candidate = base64.b64decode(raw)
                    if len(candidate) >= 17:
                        decrypted_text = decrypt_text(candidate, password_value)
                except Exception:
                    decrypted_text = None
                if decrypted_text is None:
                    try:
                        candidate2 = raw.encode('latin-1')
                        decrypted_text = decrypt_text(candidate2, password_value)
                    except Exception:
                        decrypted_text = None
                if decrypted_text is None:
                    QMessageBox.critical(self, "Error", "Failed to decrypt the provided text. It may be corrupted or password is wrong.")
                    return
                save_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted Text", "", "Text Files (*.txt);;All Files (*)")
                if save_path:
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(decrypted_text)
                    QMessageBox.information(self, "Done", "Text decrypted and saved successfully ✅")
                return
            if hasattr(self, "save_file300") and os.path.isfile(self.save_file300):
                if not self.is_encrypted_file(self.save_file300):
                    QMessageBox.warning(self, "Error", "This file is not encrypted ❌")
                    return
                with open(self.save_file300, "rb") as f:
                    encrypted_data = f.read()
                try:
                    decrypted_text = decrypt_text(encrypted_data, password_value)
                except InvalidToken:
                    QMessageBox.critical(self, "Error", "Wrong password or corrupted file.")
                    return
                save_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File", "", "Decrypted Files (*.txt);;All Files (*)")
                if save_path:
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(decrypted_text)
                    QMessageBox.information(self, "Done", "File decrypted and saved successfully ✅")
                return
            QMessageBox.warning(self, "Error", "No data found to decrypt.")
        except InvalidToken:
            QMessageBox.critical(self, "Error", "Wrong password or corrupted data.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed:\n{str(e)}")
    def go_back1(self):
        self.close()
        self.main_window.show()
    def keyPressEvent(self, event):
        # Ctrl+D => decrypt
        if event.modifiers() == Qt.ControlModifier and event.key() == Qt.Key_D:
            if not self.decrypt_button.isEnabled():
                QMessageBox.information(self, "Info", "You must enter password first.")
            else:
                self.decrypt_action()
        elif event.modifiers() == Qt.ControlModifier and event.key() == Qt.Key_O:
            self.open_file_dialog2()
        elif event.key() == Qt.Key_Escape:
            if hasattr(self, "paswo1"):
                try:
                    self.paswo1.tech1m.clear()
                except Exception:
                    pass
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("mo-crypt")
        self.resize(600, 750)
        self.setFixedSize(600, 750)
        try:
            self.setWindowIcon(QIcon("mo-crypt icon.png"))
        except:
            pass
        lab1 = QLabel("Mo-crypt", self)
        lab1.setGeometry(0, 0, 600, 160)
        lab1.setFont(QFont("Amasis MT Pro Black", 50))
        lab1.setStyleSheet("color:Black; background-color:blue;")
        lab1.setAlignment(Qt.AlignCenter)
        lab2 = QLabel("what do you want:", self)
        lab2.setGeometry(10, 170, 600, 210)
        lab2.setFont(QFont("Arial", 15))
        self.but1 = QPushButton("Encrypt", self)
        self.but2 = QPushButton("Decrypt", self)
        self.initUI()
    def initUI(self):
        self.but1.setGeometry(10, 300, 290, 250)
        self.but2.setGeometry(310, 300, 290, 250)
        self.but1.setStyleSheet("font-size:40px; background-color:white;")
        self.but2.setStyleSheet("font-size:40px; background-color:white;")
        try:
            self.but1.setIcon(QIcon("pngtree-lock-line-icon-vector-png-image_1859174.jpg"))
            self.but1.setIconSize(QSize(80, 40))
            self.but2.setIcon(QIcon("pngtree-flat-style-key-icon-with-password-vector-illustration-on-a-white-png-image_12387660.png"))
            self.but2.setIconSize(QSize(80, 40))
        except:
            pass
        self.but1.clicked.connect(self.is_clicked1)
        self.but2.clicked.connect(self.is_clicked2)
    def is_clicked1(self):
        self.hide()
        self.encrypt_window = Encrypt_window(self)
        self.encrypt_window.show()
    def is_clicked2(self):
        self.hide()
        self.decrypt_window = Decrypt_window(self)
        self.decrypt_window.show()
def Main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
if __name__ == '__main__':
    Main()
