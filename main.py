import math
import sys
from PySide6.QtWidgets import *
from PySide6.QtCore import *
from PySide6.QtUiTools import *
import sympy
import hashlib

class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        loader = QUiLoader()
        self.ui = loader.load("form.ui",None)
        self.ui.show()
        self.ui.btn_generate.clicked.connect(self.generate_key)
        self.ui.btn_encrypt_rsa.clicked.connect(self.encrypt_rsa)
        self.ui.btn_decrypt_rsa.clicked.connect(self.decrypt_rsa)
        self.ui.btn_signing_rsa.clicked.connect(self.signing)
        self.ui.btn_verification_rsa.clicked.connect(self.verification)
        self.ui.btn_hash.clicked.connect(self.hashing)
        self.ui.btn_clean_en.clicked.connect(self.clean_en)
        self.ui.btn_clean_de.clicked.connect(self.clean_de)
        self.ui.btn_clean_sig.clicked.connect(self.clean_sig)
        self.ui.btn_clean_ver.clicked.connect(self.clean_ver)
        self.ui.btn_clean_gen.clicked.connect(self.clean_gen)
        self.ui.btn_clean_hash.clicked.connect(self.clean_hash)
        self.ui.about.triggered.connect(self.about)
        self.ui.help_2.triggered.connect(self.help)
        self.ui.exit.triggered.connect(exit)

    def generate_key(self):
        p = sympy.randprime(5,100)
        q = sympy.randprime(5,100)
        n = p*q
        phi = (p-1)*(q-1)
        e = sympy.randprime(2,phi)
        d = self.GF(phi,e)
        self.ui.text_private.setPlainText(f"{d}.{p}.{q}")
        self.ui.text_public.setPlainText(f"{e}.{n}")
        timer = QTimer(self)
        timer.timeout.connect(self.clean_gen)
        timer.start(20000)

    def GF(self,phi,e):
        a1,a2,a3 = 1,0,phi
        b1,b2,b3 = 0,1,e
        while b3>=1:
            q = a3//b3
            t1,t2,t3 = a1 -(q*b1),a2 - (q*b2),a3 - (q*b3)
            a1,a2,a3 = b1,b2,b3
            b1,b2,b3 = t1,t2,t3
            if b3==1:
                if b2>=0:
                    return b2
                elif b2<0:
                    return b2+phi

    def encrypt_rsa(self):
        arr_encrypt = []
        en = ""
        plaintext = self.ui.textbox_plain_rsa.toPlainText()
        public_key = self.ui.textbox_public_rsa.toPlainText()
        public_key = public_key.split(".")
        e,n = public_key[0],public_key[1]
        for i in plaintext:
            arr_encrypt.append(ord(i))
        for i in arr_encrypt:
            res = (i**int(e))%int(n)
            en=en + chr(res)
        self.ui.textbox_cipher_rsa.setPlainText(en)

    def decrypt_rsa(self):
        arr_decrypt = []
        de = ""
        ciphertext = self.ui.textbox_cipher_rsa_de.toPlainText()
        private_key = self.ui.textbox_Private_rsa.toPlainText()
        private_key = private_key.split(".")
        d,p,q = private_key[0],private_key[1],private_key[2]
        n = int(p) * int(q)
        for i in ciphertext:
            arr_decrypt.append(ord(i))
        for i in arr_decrypt:
            res = (i**int(d))%n
            de = de + chr(res)
        self.ui.textbox_plain_rsa_de.setPlainText(de)

    def signing(self):
        arr_sign = []
        si =""
        plaintext = self.ui.textbox_plain_sign_rsa.toPlainText()
        private_key = self.ui.textbox_private_sign_rsa.toPlainText()
        private_key = private_key.split(".")
        d,p,q = private_key[0],private_key[1],private_key[2]
        n = int(p) * int(q)
        for i in plaintext:
            arr_sign.append(ord(i))
        for i in arr_sign:
            res = (i**int(d))%n
            si=si + chr(res)
        self.ui.textbox_signed_rsa.setPlainText(si)

    def verification(self):
        arr_verification = []
        ver =""
        plaintext = self.ui.textbox_plain_veri_rsa.toPlainText()
        signed_text = self.ui.textbox_signed_veri_rsa.toPlainText()
        public_key = self.ui.textbox_public_veri_rsa.toPlainText()
        public_key = public_key.split(".")
        e,n = public_key[0],public_key[1]
        for i in signed_text:
            arr_verification.append(ord(i))
        for i in arr_verification:
            res = (i**int(e))%int(n)
            ver=ver + chr(res)
        if ver == plaintext:
            msg = QMessageBox()
            msg.setText("Message Authentication")
            msg.setInformativeText("The authenticity of the message has been confirmed")
            msg.setIcon(QMessageBox.Information)
            msg.setWindowTitle("Authentication")
            msg.exec()
        else:
            msg = QMessageBox()
            msg.setText("Message Authentication")
            msg.setInformativeText("The authenticity of the message has not been confirmed")
            msg.setIcon(QMessageBox.Critical)
            msg.setWindowTitle("Authentication")
            msg.exec()

    def hashing(self):
        if self.ui.combobox.currentText()=="MD5":
            plaintext = self.ui.text_plain_hash.toPlainText()
            hash = hashlib.md5(plaintext.encode())
            self.ui.text_hashed_hash.setPlainText(hash.hexdigest())
        elif self.ui.combobox.currentText()=="SHA-1":
            plaintext = self.ui.text_plain_hash.toPlainText()
            hash = hashlib.sha1(plaintext.encode())
            self.ui.text_hashed_hash.setPlainText(hash.hexdigest())
        elif self.ui.combobox.currentText()=="SHA-224":
            plaintext = self.ui.text_plain_hash.toPlainText()
            hash = hashlib.sha224(plaintext.encode())
            self.ui.text_hashed_hash.setPlainText(hash.hexdigest())
        elif self.ui.combobox.currentText()=="SHA-256":
            plaintext = self.ui.text_plain_hash.toPlainText()
            hash = hashlib.sha256(plaintext.encode())
            self.ui.text_hashed_hash.setPlainText(hash.hexdigest())
        elif self.ui.combobox.currentText()=="SHA-384":
            plaintext = self.ui.text_plain_hash.toPlainText()
            hash = hashlib.sha384(plaintext.encode())
            self.ui.text_hashed_hash.setPlainText(hash.hexdigest())
        elif self.ui.combobox.currentText()=="SHA-512":
            plaintext = self.ui.text_plain_hash.toPlainText()
            hash = hashlib.sha512(plaintext.encode())
            self.ui.text_hashed_hash.setPlainText(hash.hexdigest())

    def clean_en(self):
        self.ui.textbox_plain_rsa.setPlainText("")
        self.ui.textbox_public_rsa.setPlainText("")
        self.ui.textbox_cipher_rsa.setPlainText("")

    def clean_de(self):
        self.ui.textbox_cipher_rsa_de.setPlainText("")
        self.ui.textbox_Private_rsa.setPlainText("")
        self.ui.textbox_plain_rsa_de.setPlainText("")
    
    def clean_sig(self):
        self.ui.textbox_plain_sign_rsa.setPlainText("")
        self.ui.textbox_private_sign_rsa.setPlainText("")
        self.ui.textbox_signed_rsa.setPlainText("")
    
    def clean_ver(self):
        self.ui.textbox_plain_veri_rsa.setPlainText("")
        self.ui.textbox_signed_veri_rsa.setPlainText("")
        self.ui.textbox_public_veri_rsa.setPlainText("")
        self.ui.textbox_verification_rsa.setPlainText("")

    def clean_gen(self):
        self.ui.text_public.setPlainText("")
        self.ui.text_private.setPlainText("")

    def clean_hash(self):
        self.ui.text_plain_hash.setPlainText("")
        self.ui.text_hashed_hash.setPlainText("")

    def about(self):
        msg = QMessageBox()
        msg.setText("Cryptography")
        msg.setInformativeText("GUI Cryptography using Pyside6\ninclude:\n    - RSA Cryptography\n    - RSA Digital Signature\n    - Hashing\n    - Message authentication code\n\nVersion 1.4\nThis program was developed by Alireza Kiaeipour\nContact developer: a.kiaipoor@gmail.com\nBuilt in 2021")
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle("about")
        msg.exec()

    def help(self):
        msg = QMessageBox()
        msg.setText("Cryptography")
        msg.setInformativeText("Generate Key:\nYou can generate public and private keys in the key generation section.\nThe public and private keys expire after 20 seconds.\n\nRSA Cryptography:\nYou can use the public key to encrypt the message, and you can use the private key to decrypt the encrypted message.\n\nRSA Digital Signature:\nUsing the private key you can sign the message and the sender sends the message and the signed message to the recipient.\n\nRSA Signature Verification:\nThe recipient uses the public key to convert the signed message into an unsigned message and compare it with the original message.\n\nHash:\nYou can hash the message using the MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 algorithms.")
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle("help")
        msg.exec()
       
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Main()
    app.exec()