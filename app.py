from flask import Flask, request, send_file, render_template, flash, redirect, url_for
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import os, io, zipfile
from stegano import lsb
import hashlib
import hmac
import re 

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Important for flash messages
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

KEY_SIZE = 32
IV_SIZE = 16
SALT_SIZE = 16
HMAC_SIZE = 32
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'txt', 'pdf', 'doc', 'docx', 'ppt', 'pptx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Password Policy Regex (at least 6 characters, mix of letters, numbers, and symbols)
PASSWORD_REGEX = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$"

def pad(data):
    pad_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    return data[:-data[-1]]

def encrypt_file(file_data, password):
    salt = os.urandom(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=KEY_SIZE)
    iv = os.urandom(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(file_data))

    # Generate HMAC-SHA256 for integrity verification
    hmac_key = hashlib.sha256(password.encode()).digest()
    hmac_data = iv + encrypted_data + salt
    hmac_digest = hmac.new(hmac_key, hmac_data, hashlib.sha256).digest()

    return hmac_data + hmac_digest  # Append HMAC to encrypted data

def decrypt_file(encrypted_data, password):
    hmac_digest = encrypted_data[-HMAC_SIZE:]
    hmac_data = encrypted_data[:-HMAC_SIZE]

    iv = hmac_data[:IV_SIZE]
    salt = hmac_data[-SALT_SIZE:]
    encrypted_content = hmac_data[IV_SIZE:-SALT_SIZE]

    key = PBKDF2(password, salt, dkLen=KEY_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Verify HMAC-SHA256
    hmac_key = hashlib.sha256(password.encode()).digest()
    computed_hmac = hmac.new(hmac_key, hmac_data, hashlib.sha256).digest()
    if not hmac.compare_digest(computed_hmac, hmac_digest):
        raise ValueError("HMAC verification failed! Data integrity compromised.")

    return unpad(cipher.decrypt(encrypted_content))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/hide', methods=['POST'])
def hide_file():
    if 'image' not in request.files or 'file' not in request.files:
        flash("No file part", "error")
        return redirect(url_for('index'))

    image = request.files['image']
    file = request.files['file']

    if not allowed_file(image.filename) or not allowed_file(file.filename):
        flash("Invalid file type", "error")
        return redirect(url_for('index'))

    password = request.form['password']
    stealth_mode = 'stealth_mode' in request.form

    if stealth_mode and 'decoy_image' not in request.files:
        flash("No decoy image for stealth mode", "error")
        return redirect(url_for('index'))
    
    if not re.match(PASSWORD_REGEX, password):
        flash("Password does not meet the required complexity.", "error")
        return redirect(url_for('index'))

    image_path = os.path.join(UPLOAD_FOLDER, secure_filename(image.filename))
    image.save(image_path)

    file_data = file.read()
    encrypted_file_data = encrypt_file(file_data, password)

    hidden_image_path = image_path + "_hidden.png"
    lsb.hide(image_path, encrypted_file_data.hex()).save(hidden_image_path)

    if stealth_mode:
        decoy_image = request.files['decoy_image']
        decoy_path = os.path.join(UPLOAD_FOLDER, secure_filename(decoy_image.filename))
        decoy_image.save(decoy_path)

        encrypted_decoy_data = encrypt_file(open(hidden_image_path, 'rb').read(), password)
        lsb.hide(decoy_path, encrypted_decoy_data.hex()).save(hidden_image_path)

    return send_file(hidden_image_path, as_attachment=True)

@app.route('/extract', methods=['POST'])
def extract_file():
    if 'image' not in request.files:
        flash("No image file", "error")
        return redirect(url_for('index'))

    image = request.files['image']
    password = request.form['password']
    
    if not allowed_file(image.filename):
        flash("Invalid file type", "error")
        return redirect(url_for('index'))
    
    if not re.match(PASSWORD_REGEX, password):
        flash("Password does not meet the required complexity.", "error")
        return redirect(url_for('index'))

    image_path = os.path.join(UPLOAD_FOLDER, secure_filename(image.filename))
    image.save(image_path)

    try:
        extracted_data = bytes.fromhex(lsb.reveal(image_path))
        decrypted_data = decrypt_file(extracted_data, password)

        if b"PNG" in decrypted_data:
            hidden_image_path = os.path.join(UPLOAD_FOLDER, "hidden_image.png")
            with open(hidden_image_path, "wb") as img_file:
                img_file.write(decrypted_data)

            hidden_extracted_data = bytes.fromhex(lsb.reveal(hidden_image_path))
            hidden_decrypted_data = decrypt_file(hidden_extracted_data, password)

            decoy_image_path = os.path.join(UPLOAD_FOLDER, "decoy_image.png")
            with open(decoy_image_path, "wb") as img_file:
                img_file.write(open(image_path, "rb").read())

            secret_file_path = os.path.join(UPLOAD_FOLDER, "secret_file")
            with open(secret_file_path, "wb") as file:
                file.write(hidden_decrypted_data)

            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(decoy_image_path, "decoy_image.png")
                zipf.write(hidden_image_path, "hidden_image.png")
                zipf.write(secret_file_path, "secret_file")
            zip_buffer.seek(0)

            os.remove(image_path)
            os.remove(hidden_image_path)
            os.remove(decoy_image_path)
            os.remove(secret_file_path)

            return send_file(zip_buffer, as_attachment=True, download_name="extracted_files.zip")

        else:
            os.remove(image_path)
            return send_file(io.BytesIO(decrypted_data), as_attachment=True, download_name="extracted_file")

    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for('index'))
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)