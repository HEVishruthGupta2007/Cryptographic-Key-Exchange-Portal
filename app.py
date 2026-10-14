from flask import (

    Flask,

    render_template,

    request,

    redirect,

    url_for,

    flash,

    session,

    send_file

)

from werkzeug.security import (

    generate_password_hash,

    check_password_hash

)

from flask_wtf.csrf import CSRFProtect

from werkzeug.utils import secure_filename

from io import BytesIO

import os

import uuid

from config import SECRET_KEY

from database import get_connection

from crypto_utils import (

    encrypt_private_key,

    decrypt_private_key,

)

from crypto_utils import (

    generate_key,

    encrypt_data,

    decrypt_data,

    generate_rsa_key_pair,

    encrypt_key_with_rsa,

    decrypt_key_with_rsa,

    encrypt_private_key,

    decrypt_private_key,

)

# =========================================================

# FLASK APPLICATION

# =========================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = SECRET_KEY

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

app.config["SESSION_COOKIE_HTTPONLY"] = True

app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_SECURE"] = False

csrf = CSRFProtect(app)

# =========================================================

# SECURITY SETTINGS

# =========================================================

# Allowed file types

ALLOWED_EXTENSIONS = {

    "txt",

    "pdf",

    "doc",

    "docx",

    "xls",

    "xlsx",

    "ppt",

    "pptx",

    "jpg",

    "jpeg",

    "png",

    "gif",

    "zip",

    "csv"

}

def allowed_file(filename):

    if "." not in filename:

        return False

    extension = filename.rsplit(

        ".",

        1

    )[1].lower()

    return extension in ALLOWED_EXTENSIONS

# =========================================================

# AUDIT LOGGING

# =========================================================

def log_activity(

    action,

    description="",

    user_email=None

):

    connection = None

    cursor = None

    try:

        connection = get_connection()

        cursor = connection.cursor()

        ip_address = request.remote_addr

        cursor.execute(

            """

            INSERT INTO audit_logs

            (

                user_email,

                action,

                description,

                ip_address

            )

            VALUES

            (

                %s,

                %s,

                %s,

                %s

            )

            """,

            (

                user_email,

                action,

                description,

                ip_address

            )

        )

        connection.commit()

    except Exception:

        app.logger.exception("Audit logging failed")

    finally:

        if cursor:

            cursor.close()

        if connection:

            connection.close()

# =========================================================

# HOME PAGE

# =========================================================

@app.route("/")

def home():

    return render_template(

        "index.html"

    )

# =========================================================

# FILE SIZE ERROR

# =========================================================

@app.errorhandler(413)

def file_too_large(error):

    flash(

        "File is too large. Maximum allowed size is 10 MB.",

        "danger"

    )

    return redirect(

        url_for("upload_file")

    )

# =========================================================

# INTERNAL SERVER ERROR

# =========================================================

@app.errorhandler(500)

def internal_server_error(error):

    app.logger.error("Internal Server Error: %s", error)

    flash(

        "Something went wrong. Please try again.",

        "danger"

    )

    return redirect(

        url_for("home")

    )

# =========================================================

# USER REGISTRATION

# =========================================================

@app.route(

    "/register",

    methods=["GET", "POST"]

)

def register():

    if request.method == "POST":

        name = request.form.get(

            "name",

            ""

        ).strip()

        mobile = request.form.get(

            "mobile",

            ""

        ).strip()

        email = request.form.get(

            "email",

            ""

        ).strip().lower()

        password = request.form.get(

            "password",

            ""

        )

        confirm_password = request.form.get(

            "confirm_password",

            ""

        )

        # -------------------------------------------------

        # Validate fields

        # -------------------------------------------------

        if (

            not name

            or not mobile

            or not email

            or not password

        ):

            flash(

                "All fields are required.",

                "danger"

            )

            return redirect(

                url_for("register")

            )

        if password != confirm_password:

            flash(

                "Passwords do not match.",

                "danger"

            )

            return redirect(

                url_for("register")

            )

        connection = None

        cursor = None

        try:

            connection = get_connection()

            cursor = connection.cursor()

            # -------------------------------------------------

            # Check existing user

            # -------------------------------------------------

            cursor.execute(

                """

                SELECT id

                FROM users

                WHERE email = %s

                """,

                (email,)

            )

            existing_user = cursor.fetchone()

            if existing_user:

                flash(

                    "An account with this email already exists.",

                    "warning"

                )

                return redirect(

                    url_for("register")

                )

            # -------------------------------------------------

            # Hash password

            # -------------------------------------------------

            password_hash = generate_password_hash(

                password

            )

            # -------------------------------------------------

            # Generate RSA key pair

            # -------------------------------------------------

            private_key, public_key = generate_rsa_key_pair()

            encrypted_private_key = encrypt_private_key(private_key)

            # -------------------------------------------------

            # Insert user

            # -------------------------------------------------

            cursor.execute(

                """

                INSERT INTO users

                (

                    name,

                    mobile,

                    email,

                    password_hash,

                    public_key,

                    private_key

                )

                VALUES

                (

                    %s,

                    %s,

                    %s,

                    %s,

                    %s,

                    %s

                )

                """,

                (

                    name,

                    mobile,

                    email,

                    password_hash,

                    public_key,

                    encrypted_private_key

                )

            )

            connection.commit()

            log_activity(

            "REGISTRATION",

            "New user account created.",

            email

            )

            flash(

                "Registration successful. Please login.",

                "success"

            )

            return redirect(

                url_for("login")

            )

        except Exception:

            if connection:

                connection.rollback()

            app.logger.exception("User registration failed")

            flash(

                "Registration failed. Please try again.",

                "danger"

            )

            return redirect(

                url_for("register")

            )

        finally:

            if cursor:

                cursor.close()

            if connection:

                connection.close()

    return render_template(

        "auth/register.html"

    )

# =========================================================

# USER LOGIN

# =========================================================

@app.route(

    "/login",

    methods=["GET", "POST"]

)

def login():

    if request.method == "POST":

        email = request.form.get(

            "email",

            ""

        ).strip().lower()

        password = request.form.get(

            "password",

            ""

        )

        connection = None

        cursor = None

        try:

            connection = get_connection()

            cursor = connection.cursor(

                dictionary=True

            )

            cursor.execute(

                """

                SELECT

                    id,

                    name,

                    email,

                    password_hash

                FROM users

                WHERE email = %s

                """,

                (email,)

            )

            user = cursor.fetchone()

            if (

                user

                and check_password_hash(

                    user["password_hash"],

                    password

                )

            ):

                session.clear()

                session["user_id"] = user["id"]

                session["user_name"] = user["name"]

                session["user_email"] = user["email"]

                # Log successful login

                log_activity(

                    "LOGIN",

                    "User logged in successfully.",

                    user["email"]

                )

                flash(

                    "Login successful.",

                    "success"

                )

                return redirect(

                    url_for("user_dashboard")

                )

            flash(

                "Invalid email or password.",

                "danger"

            )

            return redirect(

                url_for("login")

            )

        except Exception:

            app.logger.exception("Authentication operation failed")

            flash(

                "Unable to log in right now. Please try again.",

                "danger"

            )

            return redirect(

                url_for("login")

            )

        finally:

            if cursor:

                cursor.close()

            if connection:

                connection.close()

    return render_template(

        "auth/login.html"

    )

# =========================================================

# USER DASHBOARD

# =========================================================

@app.route("/dashboard")

def user_dashboard():

    if "user_id" not in session:

        flash(

            "Please login first.",

            "warning"

        )

        return redirect(

            url_for("login")

        )

    return render_template(

        "user/dashboard.html"

    )

# =========================================================

# USER PROFILE

# =========================================================

@app.route("/profile")

def profile():

    if "user_id" not in session:

        flash(

            "Please login first.",

            "warning"

        )

        return redirect(

            url_for("login")

        )

    connection = None

    cursor = None

    try:

        connection = get_connection()

        cursor = connection.cursor(

            dictionary=True

        )

        cursor.execute(

            """

            SELECT

                id,

                name,

                mobile,

                email,

                created_at,

                public_key

            FROM users

            WHERE id = %s

            """,

            (

                session["user_id"],

            )

        )

        user = cursor.fetchone()

        if user is None:

            flash(

                "User profile not found.",

                "danger"

            )

            return redirect(

                url_for("user_dashboard")

            )

        return render_template(

            "user/profile.html",

            user=user

        )

    except Exception:

        app.logger.exception("Profile loading failed")

        flash(

            "Unable to load your profile. Please try again.",

            "danger"

        )

        return redirect(

            url_for("user_dashboard")

        )

    finally:

        if cursor:

            cursor.close()

        if connection:

            connection.close()

# =========================================================

# UPLOAD AND SECURE FILE EXCHANGE

# =========================================================

@app.route(

    "/upload",

    methods=["GET", "POST"]

)

def upload_file():

    # -------------------------------------------------

    # Check login

    # -------------------------------------------------

    if "user_id" not in session:

        flash(

            "Please login first.",

            "warning"

        )

        return redirect(

            url_for("login")

        )

    # =================================================

    # GET REQUEST

    # Load recipient users

    # =================================================

    if request.method == "GET":

        connection = None

        cursor = None

        try:

            connection = get_connection()

            cursor = connection.cursor(

                dictionary=True

            )

            cursor.execute(

                """

                SELECT

                    name,

                    email

                FROM users

                WHERE email != %s

                ORDER BY name

                """,

                (

                    session["user_email"],

                )

            )

            users = cursor.fetchall()

            return render_template(

                "user/upload.html",

                users=users

            )

        except Exception:

            app.logger.exception("Recipient list loading failed")

            flash(

                "Unable to load recipients. Please try again.",

                "danger"

            )

            return redirect(

                url_for("user_dashboard")

            )

        finally:

            if cursor:

                cursor.close()

            if connection:

                connection.close()

    # =================================================

    # POST REQUEST

    # Encrypt and send file

    # =================================================

    uploaded_file = request.files.get(

        "file"

    )

    recipient_email = request.form.get(

        "recipient_email",

        ""

    ).strip().lower()

    # -------------------------------------------------

    # Validate file

    # -------------------------------------------------

    if (

        uploaded_file is None

        or uploaded_file.filename == ""

    ):

        flash(

            "Please select a file.",

            "danger"

        )

        return redirect(

            url_for("upload_file")

        )

    # -------------------------------------------------

    # Validate file type

    # -------------------------------------------------

    if not allowed_file(

        uploaded_file.filename

    ):

        flash(

            "File type is not allowed.",

            "danger"

        )

        return redirect(

            url_for("upload_file")

        )

    # -------------------------------------------------

    # Validate recipient

    # -------------------------------------------------

    if not recipient_email:

        flash(

            "Please select a recipient.",

            "danger"

        )

        return redirect(

            url_for("upload_file")

        )

    # -------------------------------------------------

    # Sanitize filename

    # -------------------------------------------------

    safe_filename = secure_filename(

        uploaded_file.filename

    )

    if not safe_filename:

        flash(

            "Invalid filename.",

            "danger"

        )

        return redirect(

            url_for("upload_file")

        )

    connection = None

    cursor = None

    encrypted_path = None

    try:

        # =================================================

        # Read file

        # =================================================

        file_data = uploaded_file.read()

        if not file_data:

            flash(

                "The selected file is empty.",

                "danger"

            )

            return redirect(

                url_for("upload_file")

            )

        # =================================================

        # Database connection

        # =================================================

        connection = get_connection()

        cursor = connection.cursor(

            dictionary=True

        )

        # =================================================

        # Find recipient

        # =================================================

        cursor.execute(

            """

            SELECT

                id,

                email,

                public_key

            FROM users

            WHERE email = %s

            """,

            (

                recipient_email,

            )

        )

        recipient = cursor.fetchone()

        if recipient is None:

            flash(

                "Recipient user was not found.",

                "danger"

            )

            return redirect(

                url_for("upload_file")

            )

        # =================================================

        # Check recipient RSA public key

        # =================================================

        if not recipient["public_key"]:

            flash(

                "Recipient does not have an RSA public key.",

                "danger"

            )

            return redirect(

                url_for("upload_file")

            )

        # =================================================

        # Generate AES-256 key

        # =================================================

        aes_key = generate_key()

        # =================================================

        # Encrypt file using AES-256-GCM

        # =================================================

        nonce, ciphertext, tag = encrypt_data(

            file_data,

            aes_key

        )

        # =================================================

        # Encrypt AES key using recipient RSA public key

        # =================================================

        encrypted_aes_key = encrypt_key_with_rsa(

            aes_key,

            recipient["public_key"]

        )

        encrypted_key_hex = (

            encrypted_aes_key.hex()

        )

        # =================================================

        # Create random encrypted filename

        # =================================================

        encrypted_filename = (

            str(uuid.uuid4()) + ".enc"

        )

        os.makedirs(

            "encrypted_files",

            exist_ok=True

        )

        encrypted_path = os.path.join(

            "encrypted_files",

            encrypted_filename

        )

        # =================================================

        # Store encrypted file

        #

        # Format:

        # [nonce][tag][ciphertext]

        # =================================================

        with open(

            encrypted_path,

            "wb"

        ) as encrypted_file:

            encrypted_file.write(

                nonce

            )

            encrypted_file.write(

                tag

            )

            encrypted_file.write(

                ciphertext

            )

        # =================================================

        # Store file information

        # =================================================

        cursor.execute(

            """

            INSERT INTO secure_files

            (

                original_filename,

                encrypted_filename,

                owner_email

            )

            VALUES

            (

                %s,

                %s,

                %s

            )

            """,

            (

                safe_filename,

                encrypted_filename,

                session["user_email"]

            )

        )

        file_id = cursor.lastrowid

        # =================================================

        # Store encrypted AES key for recipient

        # =================================================

        cursor.execute(

            """

            INSERT INTO file_keys

            (

                file_id,

                encrypted_key,

                recipient_email

            )

            VALUES

            (

                %s,

                %s,

                %s

            )

            """,

            (

                file_id,

                encrypted_key_hex,

                recipient_email

            )

        )

        # =================================================

        # Also encrypt AES key for sender

        # =================================================

        sender_email = session["user_email"]

        cursor.execute(

            """

            SELECT public_key

            FROM users

            WHERE email = %s

            """,

            (

                sender_email,

            )

        )

        sender = cursor.fetchone()

        if (

            sender is None

            or not sender["public_key"]

        ):

            raise Exception(

                "Sender RSA public key was not found."

            )

        sender_encrypted_key = (

            encrypt_key_with_rsa(

                aes_key,

                sender["public_key"]

            )

        )

        sender_encrypted_key_hex = (

            sender_encrypted_key.hex()

        )

        cursor.execute(

            """

            INSERT INTO file_keys

            (

                file_id,

                encrypted_key,

                recipient_email

            )

            VALUES

            (

                %s,

                %s,

                %s

            )

            """,

            (

                file_id,

                sender_encrypted_key_hex,

                sender_email

            )

        )

        # =================================================

        # Commit transaction

        # =================================================

        connection.commit()

        flash(

            "File encrypted and securely sent.",

            "success"

        )

        return redirect(

            url_for("my_files")

        )

    except Exception:

        if connection:

            connection.rollback()

        # -------------------------------------------------

        # Remove encrypted file if operation failed

        # -------------------------------------------------

        if (

            encrypted_path

            and os.path.exists(encrypted_path)

        ):

            try:

                os.remove(

                    encrypted_path

                )

            except Exception:

                pass

        app.logger.exception("Secure file upload failed")

        flash(

            "File upload failed. Please try again.",

            "danger"

        )

        return redirect(

            url_for("upload_file")

        )

    finally:

        if cursor:

            cursor.close()

        if connection:

            connection.close()

# =========================================================

# MY FILES

# =========================================================

@app.route("/files")

def my_files():

    if "user_id" not in session:

        flash(

            "Please login first.",

            "warning"

        )

        return redirect(

            url_for("login")

        )

    connection = None

    cursor = None

    try:

        connection = get_connection()

        cursor = connection.cursor(

            dictionary=True

        )

        cursor.execute(

            """

            SELECT DISTINCT

                sf.id,

                sf.original_filename,

                sf.encrypted_filename,

                sf.owner_email,

                sf.uploaded_at

            FROM secure_files sf

            LEFT JOIN file_keys fk

                ON sf.id = fk.file_id

            WHERE

                sf.owner_email = %s

                OR fk.recipient_email = %s

            ORDER BY sf.uploaded_at DESC

            """,

            (

                session["user_email"],

                session["user_email"]

            )

        )

        files = cursor.fetchall()

        return render_template(

            "user/files.html",

            files=files

        )

    except Exception:

        app.logger.exception("User file list loading failed")

        flash(

            "Unable to load files. Please try again.",

            "danger"

        )

        return redirect(

            url_for("user_dashboard")

        )

    finally:

        if cursor:

            cursor.close()

        if connection:

            connection.close()

# =========================================================

# DOWNLOAD AND DECRYPT FILE

# =========================================================

@app.route(

    "/download/<int:file_id>"

)

def download_file(file_id):

    if "user_id" not in session:

        flash(

            "Please login first.",

            "warning"

        )

        return redirect(

            url_for("login")

        )

    connection = None

    cursor = None

    try:

        connection = get_connection()

        cursor = connection.cursor(

            dictionary=True

        )

        # =================================================

        # Get file information

        # =================================================

        cursor.execute(

            """

            SELECT

                id,

                original_filename,

                encrypted_filename,

                owner_email

            FROM secure_files

            WHERE id = %s

            """,

            (

                file_id,

            )

        )

        file_record = cursor.fetchone()

        if file_record is None:

            flash(

                "File not found.",

                "danger"

            )

            return redirect(

                url_for("my_files")

            )

        # =================================================

        # Get encrypted AES key for current user

        # =================================================

        cursor.execute(

            """

            SELECT

                encrypted_key

            FROM file_keys

            WHERE

                file_id = %s

                AND recipient_email = %s

            """,

            (

                file_id,

                session["user_email"]

            )

        )

        key_record = cursor.fetchone()

        if key_record is None:

            flash(

                "You do not have the key to decrypt this file.",

                "danger"

            )

            return redirect(

                url_for("my_files")

            )

        # =================================================

        # Get user's RSA private key

        # =================================================

        cursor.execute(

            """

            SELECT

                private_key

            FROM users

            WHERE email = %s

            """,

            (

                session["user_email"],

            )

        )

        user_record = cursor.fetchone()

        if (

            user_record is None

            or not user_record["private_key"]

        ):

            flash(

                "Your RSA private key was not found.",

                "danger"

            )

            return redirect(

                url_for("my_files")

            )

        # =================================================

        # Convert encrypted AES key from HEX

        # =================================================

        encrypted_aes_key = bytes.fromhex(

            key_record["encrypted_key"]

        )

        # =================================================

        # Decrypt AES key using RSA private key

        # =================================================

        decrypted_private_key = decrypt_private_key(

        user_record["private_key"]

        )

        aes_key = decrypt_key_with_rsa(

        encrypted_aes_key,

        decrypted_private_key

       )

        # =================================================

        # Locate encrypted file

        # =================================================

        encrypted_path = os.path.join(

            "encrypted_files",

            file_record["encrypted_filename"]

        )

        if not os.path.exists(

            encrypted_path

        ):

            flash(

                "Encrypted file is missing from storage.",

                "danger"

            )

            return redirect(

                url_for("my_files")

            )

        # =================================================

        # Read encrypted file

        # =================================================

        with open(

            encrypted_path,

            "rb"

        ) as encrypted_file:

            encrypted_data = (

                encrypted_file.read()

            )

        if len(encrypted_data) < 32:

            flash(

                "Encrypted file is corrupted.",

                "danger"

            )

            return redirect(

                url_for("my_files")

            )

        # =================================================

        # Extract nonce

        # =================================================

        nonce = encrypted_data[

            0:16

        ]

        # =================================================

        # Extract authentication tag

        # =================================================

        tag = encrypted_data[

            16:32

        ]

        # =================================================

        # Extract ciphertext

        # =================================================

        ciphertext = encrypted_data[

            32:

        ]

        # =================================================

        # Decrypt file using AES-GCM

        # =================================================

        plaintext = decrypt_data(

            nonce,

            ciphertext,

            tag,

            aes_key

        )

        # =================================================

        # Send original file

        # =================================================

        return send_file(

            BytesIO(plaintext),

            as_attachment=True,

            download_name=file_record[

                "original_filename"

            ]

        )

    except Exception:

        app.logger.exception("File download or decryption failed")

        flash(

            "Unable to decrypt this file. Check your access and try again.",

            "danger"

        )

        return redirect(

            url_for("my_files")

        )

    finally:

        if cursor:

            cursor.close()

        if connection:

            connection.close()

# =========================================================

# USER LOGOUT

# =========================================================

@app.route("/logout")

def logout():

    session.clear()

    flash(

        "You have been logged out.",

        "success"

    )

    return redirect(

        url_for("home")

    )

# =========================================================

# ADMIN LOGIN

# =========================================================

@app.route(

    "/admin-login",

    methods=["GET", "POST"]

)

def admin_login():

    if request.method == "POST":

        username = request.form.get(

            "username",

            ""

        ).strip()

        password = request.form.get(

            "password",

            ""

        )

        connection = None

        cursor = None

        try:

            connection = get_connection()

            cursor = connection.cursor(

                dictionary=True

            )

            cursor.execute(

                """

                SELECT

                    id,

                    username,

                    password_hash

                FROM admins

                WHERE username = %s

                """,

                (

                    username,

                )

            )

            admin = cursor.fetchone()

            if (

                admin

                and check_password_hash(

                    admin["password_hash"],

                    password

                )

            ):

                session.clear()

                session["admin_id"] = (

                    admin["id"]

                )

                session["admin_username"] = (

                    admin["username"]

                )

                flash(

                    "Admin login successful.",

                    "success"

                )

                return redirect(

                    url_for("admin_dashboard")

                )

            flash(

                "Invalid admin username or password.",

                "danger"

            )

            return redirect(

                url_for("admin_login")

            )

        except Exception:

            app.logger.exception("Authentication operation failed")

            flash(

                "Unable to log in right now. Please try again.",

                "danger"

            )

            return redirect(

                url_for("admin_login")

            )

        finally:

            if cursor:

                cursor.close()

            if connection:

                connection.close()

    return render_template(

        "auth/admin_login.html"

    )

# =========================================================

# ADMIN DASHBOARD

# =========================================================

@app.route("/admin/dashboard")

def admin_dashboard():

    if "admin_id" not in session:

        flash(

            "Please login as administrator.",

            "warning"

        )

        return redirect(

            url_for("admin_login")

        )

    connection = None

    cursor = None

    try:

        connection = get_connection()

        cursor = connection.cursor(

            dictionary=True

        )

        # =================================================

        # Count registered users

        # =================================================

        cursor.execute(

            """

            SELECT COUNT(*) AS total_users

            FROM users

            """

        )

        user_result = cursor.fetchone()

        total_users = (

            user_result["total_users"]

        )

        # =================================================

        # Count secure files

        # =================================================

        cursor.execute(

            """

            SELECT COUNT(*) AS total_files

            FROM secure_files

            """

        )

        file_result = cursor.fetchone()

        total_files = (

            file_result["total_files"]

        )

        # =================================================

        # Count file transfers

        # =================================================

        cursor.execute(

            """

            SELECT COUNT(*) AS total_transfers

            FROM file_keys

            """

        )

        transfer_result = (

            cursor.fetchone()

        )

        total_transfers = (

            transfer_result["total_transfers"]

        )

        return render_template(

            "admin/dashboard.html",

            total_users=total_users,

            total_files=total_files,

            total_transfers=total_transfers

        )

    except Exception:

        app.logger.exception("Admin dashboard loading failed")

        flash(

            "Unable to load dashboard statistics. Please try again.",

            "danger"

        )

        return redirect(

            url_for("admin_login")

        )

    finally:

        if cursor:

            cursor.close()

        if connection:

            connection.close()

# =========================================================

# ADMIN - VIEW USERS

# =========================================================

@app.route("/admin/users")

def admin_users():

    if "admin_id" not in session:

        flash(

            "Please login as administrator.",

            "warning"

        )

        return redirect(

            url_for("admin_login")

        )

    connection = None

    cursor = None

    try:

        connection = get_connection()

        cursor = connection.cursor(

            dictionary=True

        )

        cursor.execute(

            """

            SELECT

                id,

                name,

                mobile,

                email,

                created_at

            FROM users

            ORDER BY created_at DESC

            """

        )

        users = cursor.fetchall()

        return render_template(

            "admin/users.html",

            users=users

        )

    except Exception:

        app.logger.exception("Admin user list loading failed")

        flash(

            "Unable to load users. Please try again.",

            "danger"

        )

        return redirect(

            url_for("admin_dashboard")

        )

    finally:

        if cursor:

            cursor.close()

        if connection:

            connection.close()

# =========================================================

# ADMIN - VIEW SECURE FILES

# =========================================================

@app.route("/admin/files")

def admin_files():

    if "admin_id" not in session:

        flash(

            "Please login as administrator.",

            "warning"

        )

        return redirect(

            url_for("admin_login")

        )

    connection = None

    cursor = None

    try:

        connection = get_connection()

        cursor = connection.cursor(

            dictionary=True

        )

        cursor.execute(

            """

            SELECT

                sf.id,

                sf.original_filename,

                sf.encrypted_filename,

                sf.owner_email,

                fk.recipient_email,

                sf.uploaded_at

            FROM secure_files sf

            LEFT JOIN file_keys fk

                ON sf.id = fk.file_id

            ORDER BY sf.uploaded_at DESC

            """

        )

        files = cursor.fetchall()

        return render_template(

            "admin/files.html",

            files=files

        )

    except Exception:

        app.logger.exception("Admin secure file list loading failed")

        flash(

            "Unable to load secure files. Please try again.",

            "danger"

        )

        return redirect(

            url_for("admin_dashboard")

        )

    finally:

        if cursor:

            cursor.close()

        if connection:

            connection.close()

# =========================================================

# ADMIN LOGOUT

# =========================================================

@app.route("/admin/logout")

def admin_logout():

    session.clear()

    flash(

        "Administrator logged out.",

        "success"

    )

    return redirect(url_for("home"))

# =========================================================

# RUN APPLICATION

# =========================================================

if __name__ == "__main__":

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=False

    )
