import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import hashlib
import uuid
import ezgmail
import re
import pyodbc
from datetime import timedelta  # Import timedelta

app = Flask(__name__)

# Lấy secret_key từ biến môi trường FLASK_SECRET_KEY
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

# Nếu biến môi trường chưa được thiết lập, tạo một secret_key ngẫu nhiên an toàn
if not app.secret_key:
    app.secret_key = secrets.token_hex(32)
    print(
        f"Cảnh báo: Biến môi trường FLASK_SECRET_KEY chưa được thiết lập. Đã tạo một secret_key ngẫu nhiên cho phiên này: {app.secret_key}")
    print("Trong môi trường production, hãy thiết lập biến môi trường FLASK_SECRET_KEY để đảm bảo tính ổn định của phiên.")

# CẤU HÌNH BẢO MẬT SESSION
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Thời gian sống của session


# Cấu hình kết nối đến SQL Server
SERVER = os.environ.get('DB_SERVER', 'LTS')  # Lấy từ biến môi trường, mặc định là 'LTS'
DATABASE = os.environ.get('DB_DATABASE', 'doanmmud')  # Tương tự
USERNAME = os.environ.get('DB_USERNAME', 'mmud')
PASSWORD = os.environ.get('DB_PASSWORD', '11032005')
DRIVER = '{ODBC Driver 17 for SQL Server}'  # Hoặc phiên bản Driver phù hợp

# Chuỗi kết nối
conn_str = f'DRIVER={DRIVER};SERVER={SERVER};DATABASE={DATABASE};UID={USERNAME};PWD={PASSWORD};'


def get_connection():
    """Gets a connection to the SQL Server database."""
    try:
        conn = pyodbc.connect(conn_str)
        return conn
    except Exception as e:
        print(f"Lỗi kết nối đến SQL Server: {e}")
        return None


def execute_query(conn, query, params=None, fetch=False):
    """
    Executes a SQL query.

    Args:
        conn (pyodbc.Connection): The database connection.
        query (str): The SQL query to execute.
        params (tuple, optional): Parameters to pass to the query. Defaults to None.
        fetch (bool, optional): Whether to fetch the results. Defaults to False.

    Returns:
        list: If fetch is True, returns a list of rows.
        None: If fetch is False.
    """
    cursor = conn.cursor()
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        if fetch:
            return cursor.fetchall()
        else:
            conn.commit()
    except Exception as e:
        print(f"Lỗi khi thực hiện truy vấn: {e}")
        conn.rollback()
        raise  # Re-raise the exception to be caught by the caller
    finally:
        cursor.close()

def create_tables():
    """Creates the necessary tables in the database if they don't exist,
    and ensures the 'is_admin' column exists in the 'users' table.
    """
    conn = get_connection()
    if conn:
        try:
            #Sử dụng một truy vấn duy nhất để tạo bảng và đảm bảo cột is_admin
            query = """
            IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'users' AND schema_name(schema_id) = 'dbo')
            BEGIN
                CREATE TABLE dbo.users (
                    username VARCHAR(50) PRIMARY KEY,
                    combined_password_phone_hash VARCHAR(255) NOT NULL,
                    encrypted_combined_password_phone_hash VARBINARY(MAX) NULL,
                    address VARBINARY(MAX) NULL,
                    phone VARBINARY(MAX) NULL,
                    email VARBINARY(MAX) NULL,
                    is_admin BIT DEFAULT 0
                );
                PRINT 'Bảng dbo.users đã được tạo.';
            END
            ELSE
            BEGIN
                PRINT 'Bảng dbo.users đã tồn tại.';
                -- Kiểm tra và thêm cột is_admin nếu chưa tồn tại
                IF NOT EXISTS (SELECT * FROM sys.columns WHERE name = 'is_admin' AND object_id = OBJECT_ID('dbo.users'))
                BEGIN
                    ALTER TABLE dbo.users
                    ADD is_admin BIT DEFAULT 0;
                    PRINT 'Cột is_admin đã được thêm vào bảng dbo.users.';
                END
            END
            """
            execute_query(conn, query)
            print("Đã kiểm tra và/hoặc tạo bảng 'dbo.users' và cột 'is_admin'.")
        except Exception as e:
            print(f"Lỗi khi tạo hoặc kiểm tra bảng: {e}")
        finally:
            conn.close()


def load_accounts():
    """Loads account data from the database and decrypts sensitive information."""
    accounts = {}
    conn = get_connection()
    if conn:
        try:
            # Mở khóa đối xứng và lấy dữ liệu
            query = """
            OPEN SYMMETRIC KEY doanmmud DECRYPTION BY PASSWORD = 'doanmmud@';
            SELECT
                username,
                combined_password_phone_hash,
                CONVERT(NVARCHAR(255), DECRYPTBYKEY(address)) AS address,
                CONVERT(VARCHAR(20), DECRYPTBYKEY(phone)) AS phone,
                CONVERT(VARCHAR(100), DECRYPTBYKEY(email)) AS email,
                is_admin
            FROM dbo.users;
            CLOSE SYMMETRIC KEY doanmmud;
            """
            rows = execute_query(conn, query, fetch=True)
            for row in rows:
                accounts[row[0]] = {
                    'combined_password_phone_hash': row[1],
                    'address': row[2],
                    'phone': row[3],
                    'email': row[4],
                    'is_admin': row[5]
                }
        except Exception as e:
            print(f"Lỗi khi tải và giải mã dữ liệu tài khoản: {e}")
        finally:
            conn.close()
    return accounts

def save_account(username, password_plaintext, address, phone, email, is_admin):
    """Saves a new account to the database, relying on SQL Server for password hashing and encryption."""
    conn = get_connection()
    if conn:
        try:
            query = """
            EXEC dbo._usp_InsertUserEncrypted
                @username = ?,
                @password = ?,  -- Truyền mật khẩu gốc
                @phone = ?,
                @address = ?,
                @email = ?,
                @is_admin = ?;
            """
            execute_query(conn, query,
                                 (username, password_plaintext, phone, address, email, is_admin))
            print(f"Đã chèn người dùng {username} thành công (mật khẩu được băm và thông tin được mã hóa bởi SQL Server).")
        except Exception as e:
            print(f"Lỗi khi lưu tài khoản bằng stored procedure: {e}")
            print(f"Error details: {e}")
            conn.rollback()
            raise
        finally:
            conn.close()

def is_password_secure(password):
    """Kiểm tra xem mật khẩu có đáp ứng các yêu cầu bảo mật không."""
    if len(password) < 8:
        return False, "Mật khẩu phải có ít nhất 8 ký tự."
    if not re.search("[a-z]", password):
        return False, "Mật khẩu phải chứa ít nhất một chữ cái viết thường."
    if not re.search("[A-Z]", password):
        return False, "Mật khẩu phải chứa ít nhất một chữ cái viết hoa."
    if not re.search("[0-9]", password):
        return False, "Mật khẩu phải chứa ít nhất một chữ số."
    return True, None


def is_phone_valid(phone):
    """Kiểm tra xem số điện thoại có đúng định dạng 10 số không."""
    return re.match(r'^\d{10}$', phone) is not None


@app.route('/')
def index():
    """Home page."""
    if 'username' in session:
        accounts = load_accounts()
        user = accounts.get(session['username'])
        if user:  # check user
            return render_template(
                'home.html',
                username=session['username'],
                is_admin=user.get('is_admin', 0),
                address=user.get('address', 'Lỗi khi tải thông tin'),
                phone=user.get('phone', 'Lỗi khi tải thông tin'),
                email=user.get('email', 'Lỗi khi tải thông tin')
            )
        else:
            return render_template(
                'home.html',
                username=session['username'],
                address='Lỗi khi tải thông tin',
                phone='Lỗi khi tải thông tin',
                email='Lỗi khi tải thông tin'
            )
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_connection()
        if conn:
            cursor = conn.cursor()
            try:
                cursor.execute("EXEC dbo._usp_VerifyUserPassword @username=?, @password=?", (username, password))
                user = cursor.fetchone()
                if user:
                    accounts = load_accounts() # Tải lại thông tin người dùng sau khi xác thực
                    session.clear()
                    session['username'] = username
                    session['is_admin'] = accounts[username]['is_admin']
                    session.permanent = True
                    return redirect(url_for('index'))
                else:
                    error = 'Sai tài khoản hoặc mật khẩu.'
            except Exception as e:
                print(f"Lỗi khi đăng nhập: {e}")
                error = 'Lỗi khi xác thực tài khoản.'
            finally:
                cursor.close()
                conn.close()
        else:
            error = 'Không thể kết nối đến cơ sở dữ liệu.'
    return render_template('login.html', error=error)

def is_email_exists(email):
    """Kiểm tra xem email đã tồn tại trong cơ sở dữ liệu hay chưa."""
    conn = get_connection()
    if conn:
        try:
            query = """
            OPEN SYMMETRIC KEY doanmmud DECRYPTION BY PASSWORD = 'doanmmud@';
            SELECT COUNT(*)
            FROM dbo.users
            WHERE CONVERT(VARCHAR(100), DECRYPTBYKEY(email)) = ?;
            CLOSE SYMMETRIC KEY doanmmud;
            """
            cursor = conn.cursor()
            cursor.execute(query, (email,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print(f"Lỗi khi kiểm tra email tồn tại: {e}")
            return True  # Trả về True để ngăn đăng ký nếu có lỗi
        finally:
            cursor.close()
            conn.close()
    return True  # Trả về True để ngăn đăng ký nếu không thể kết nối


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page."""
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        address = request.form['address']
        phone = request.form['phone']
        email = request.form['email']
        is_admin = 0  # Mặc định là người dùng thường

        # Kiểm tra email đã tồn tại chưa
        if is_email_exists(email):
            error = "Email này đã được sử dụng để đăng ký tài khoản khác."
        else:
            # Kiểm tra mật khẩu
            password_check, password_error = is_password_secure(password)
            if not password_check:
                error = password_error
            elif not is_phone_valid(phone):
                error = "Số điện thoại phải là 10 số."
            elif not phone:  # Thêm kiểm tra số điện thoại không rỗng
                error = "Vui lòng nhập số điện thoại."
            else:
                # Gửi mật khẩu gốc đến hàm save_account để SQL Server xử lý băm và mã hóa
                save_account(username, password, address, phone, email, is_admin)
                return redirect(url_for('login'))

    # Truyền lỗi về giao diện đăng ký nếu có
    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    """Logout handler."""
    session.pop('username', None)
    session.pop('is_admin', None)  # Xóa trạng thái admin khỏi session
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password page."""
    error = None
    if request.method == 'POST':
        email = request.form['email']
        accounts = load_accounts()
        user_account = None
        for username, account_data in accounts.items():  # Iterate through username and account data
            if account_data['email'] == email:
                user_account = (username, account_data)  # Store both username and account data
                break
        if user_account:
            username, account_data = user_account  # Unpack the tuple
            reset_token = str(uuid.uuid4())
            session['reset_token'] = reset_token
            session['reset_email'] = email
            session['reset_username'] = username  # Store the username
            # In a real application, you would send an email here with the reset link
            # For demonstration, we'll just print the link
            try:
                ezgmail.send(
                    email,
                    "Yêu cầu đặt lại mật khẩu",
                    f"Nhấn vào link sau để đặt lại mật khẩu: {url_for('reset_password', reset_token=reset_token, _external=True)}"
                )
                return "Một email chứa hướng dẫn đặt lại mật khẩu đã được gửi đến bạn."
            except Exception as e:
                error = f"Không thể gửi email. Lỗi: {e}"
                print(e)
        else:
            error = "Không tìm thấy tài khoản với email này."
    return render_template('forgot_password.html', error=error)


def update_password_hash(username, new_password_plaintext):
    """Updates the password hash for a given username in the database using the stored procedure."""
    conn = get_connection()
    if conn:
        try:
            query = """
            EXEC dbo._usp_UpdateUserPassword @username = ?, @new_password = ?;
            """
            execute_query(conn, query, (username, new_password_plaintext))
            print(f"Đã cập nhật mật khẩu cho người dùng {username} thành công (băm bởi SQL Server).")
        except Exception as e:
            print(f"Lỗi khi cập nhật mật khẩu cho người dùng {username}: {e}")
            conn.rollback()
            raise
        finally:
            conn.close()

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    """Change password page."""
    if 'username' not in session:
        return redirect(url_for('login'))

    error = None
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']
        username = session['username']
        accounts = load_accounts()

        password_check, password_error = is_password_secure(new_password)
        if not password_check:
            error = password_error
        elif new_password != confirm_new_password:
            error = "Mật khẩu mới và xác nhận mật khẩu không khớp."
        else:
            conn = get_connection()
            if conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("EXEC dbo._usp_VerifyUserPassword @username=?, @password=?", (username, current_password))
                    user = cursor.fetchone()
                    if user:
                        # Gọi hàm update_password_hash để cập nhật mật khẩu mới
                        try:
                            update_password_hash(username, new_password)
                            return redirect(url_for('index'))
                        except Exception as e:
                            error = f"Lỗi khi cập nhật mật khẩu: {e}"
                    else:
                        error = "Mật khẩu hiện tại không đúng."
                except Exception as e:
                    print(f"Lỗi khi đổi mật khẩu: {e}")
                    error = "Lỗi khi xác thực mật khẩu hiện tại."
                finally:
                    cursor.close()
                    conn.close()
            else:
                error = "Không thể kết nối đến cơ sở dữ liệu."

    return render_template('change_password.html', error=error)

@app.route('/reset_password/<reset_token>', methods=['GET', 'POST'])
def reset_password(reset_token):
    """Reset password page."""
    error = None
    print(f"DEBUG: reset_token từ URL: {reset_token}")
    print(f"DEBUG: reset_token trong session: {session.get('reset_token')}")
    print(f"DEBUG: reset_email trong session: {session.get('reset_email')}")
    print(f"DEBUG: reset_username trong session: {session.get('reset_username')}")
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        if not new_password or not confirm_new_password:
            error = "Vui lòng nhập đầy đủ mật khẩu mới và xác nhận."
        elif new_password != confirm_new_password:
            error = "Mật khẩu mới và xác nhận mật khẩu không khớp."
        else:
            password_check, password_error = is_password_secure(new_password)
            if not password_check:
                error = password_error
            elif 'reset_token' in session and session['reset_token'] == reset_token and \
                    'reset_email' in session and 'reset_username' in session:
                email = session['reset_email']
                username = session['reset_username']
                accounts = load_accounts()
                if username in accounts and accounts[username]['email'] == email:
                    # Gọi hàm update_password_hash để cập nhật mật khẩu mới
                    try:
                        update_password_hash(username, new_password)
                        session.pop('reset_token', None)
                        session.pop('reset_email', None)
                        session.pop('reset_username', None)
                        return render_template('reset_password_success.html')
                    except Exception as e:
                        error = f"Lỗi khi đặt lại mật khẩu: {e}"
                else:
                    error = "Mã đặt lại không hợp lệ hoặc thông tin tài khoản không khớp."
            else:
                error = "Mã đặt lại không hợp lệ hoặc đã hết hạn."
    return render_template('reset_password.html', reset_token=reset_token, error=error)

@app.route('/reset_password_success')
def reset_password_success():
    """Page to display after successful password reset."""
    return render_template('reset_password_success.html')

# Gọi hàm tạo bảng khi ứng dụng khởi động
with app.app_context():
    create_tables()

@app.route('/get_user_info')
def get_user_info():
    """API endpoint to get user info."""
    if 'username' not in session:
        return jsonify({'error': 'Chưa đăng nhập'}), 401

    accounts = load_accounts()
    user = accounts.get(session['username'])

    if not user:
        return jsonify({'error': 'Không tìm thấy tài khoản'}), 404

    return jsonify({
        'address': user.get('address', ''),
        'phone': user.get('phone', ''),
        'email': user.get('email', '')
    })


@app.route('/admin_dashboard')
def admin_dashboard():
    """Admin dashboard page."""
    if 'username' not in session:
        return redirect(url_for('login'))

    accounts = load_accounts()
    current_user = accounts.get(session['username'])
    if not current_user or not current_user.get('is_admin'):
        return "Bạn không có quyền truy cập.", 403

    return render_template('admin_dashboard.html', accounts=accounts)

@app.route('/admin/edit/<username>', methods=['GET', 'POST'])
def edit_user(username):
    """Admin edit user page."""
    if 'username' not in session:
        return redirect(url_for('login'))

    accounts = load_accounts()
    current_user = accounts.get(session['username'])
    if not current_user or not current_user.get('is_admin'):
        return "Không có quyền truy cập", 403

    if username not in accounts:
        return "Tài khoản không tồn tại", 404

    error = None
    if request.method == 'POST':
        address = request.form['address']
        phone = request.form['phone']
        email = request.form['email']
        is_admin = int(request.form.get('is_admin', 0))

        if not is_phone_valid(phone):
            error = "Số điện thoại phải là 10 số."
        elif error is None:
            # Use the stored procedure dbo._usp_InsertUserEncrypted to update.
            conn = get_connection()
            if conn:
                try:
                    query = """
                    EXEC dbo._usp_UpdateUserEncrypted
                        @username = ?,
                        @address = ?,
                        @phone = ?,
                        @email = ?,
                        @is_admin = ?;
                    """
                    cursor = conn.cursor()
                    cursor.execute(query, (username, address, phone, email, is_admin))
                    conn.commit()

                    # Cập nhật dữ liệu đã giải mã trong accounts để không cần tải lại
                    accounts[username]['address'] = address
                    accounts[username]['phone'] = phone
                    accounts[username]['email'] = email
                    accounts[username]['is_admin'] = is_admin
                    return redirect(url_for('admin_dashboard'))
                except Exception as e:
                    print(f"Lỗi khi cập nhật tài khoản bằng stored procedure: {e}")
                    error = "Lỗi khi cập nhật tài khoản."
                    conn.rollback()
                finally:
                    cursor.close()
                    conn.close()
        else:
            return render_template('edit_user.html', username=username, data=accounts[username], error=error)

    return render_template('edit_user.html', username=username, data=accounts[username], error=error)

@app.route('/admin/delete/<username>', methods=['POST'])
def delete_user(username):
    """Admin delete user handler."""
    if 'username' not in session:
        return redirect(url_for('login'))

    accounts = load_accounts()
    current_user = accounts.get(session['username'])
    if not current_user or not current_user.get('is_admin'):
        return "Không có quyền truy cập", 403

    if username == session['username']:
        return "Không thể xoá chính bạn!", 400

    if username in accounts:
        conn = get_connection()
        if conn:
            cursor = conn.cursor()
            try:
                cursor.execute("DELETE FROM dbo.users WHERE username = ?", username)
                conn.commit()
                del accounts[username]
            except Exception as e:
                print(f"Lỗi khi xóa tài khoản: {e}")
                conn.rollback()
            finally:
                cursor.close()
                conn.close()

    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, ssl_context='adhoc')