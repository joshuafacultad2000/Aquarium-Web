
"""
Full, improved Flask app for the Aquarium Supplies project.

Features:
- SQLite (via Python's sqlite3)
- CSRF protection (Flask-WTF)
- User registration/login with password hashing
- is_admin flag (CLI create-user --admin and admin UI)
- Cart stored in session, Add/Remove/Update using POST forms with CSRF
- Checkout creates orders + order_items (quantity + price snapshot)
- Admin views for orders and users, and an admin toggle UI
- Env configuration via .env.example (python-dotenv)
- CLI commands: init-db, create-user
"""
import os
import sqlite3
import uuid
import click
from functools import wraps
from datetime import datetime
from dotenv import load_dotenv
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    g,
    jsonify,
    abort,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import CSRFProtect


load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")


app.config.update(
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
    SESSION_COOKIE_HTTPONLY=os.environ.get("SESSION_COOKIE_HTTPONLY", "true").lower() == "true",
    SESSION_COOKIE_SAMESITE=os.environ.get("SESSION_COOKIE_SAMESITE", "Lax"),
)

csrf = CSRFProtect(app)

DATABASE = os.environ.get("DATABASE_PATH", os.path.join(app.root_path, "database.db"))


UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", os.path.join(app.root_path, "static", "images"))
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


def row_to_dict(row: sqlite3.Row):
    if row is None:
        return None
    return {k: row[k] for k in row.keys()}


def ensure_users_have_is_admin_column(db):
    """If users table exists but lacks is_admin column, add it."""
    try:
        cur = db.execute("PRAGMA table_info(users)")
        rows = cur.fetchall()
        cols = [r["name"] for r in rows]
        if "is_admin" not in cols:
            db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
            db.commit()
    except sqlite3.OperationalError:
        # table doesn't exist yet
        pass


def init_db():
    """Create tables and seed sample data if needed."""
    db = get_db()
    # users table (include is_admin column)
    db.execute(
        """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0
    )
    """
    )
    db.commit()
    ensure_users_have_is_admin_column(db)

    db.execute(
        """
    CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        price REAL NOT NULL DEFAULT 0,
        image TEXT,
        description TEXT
    )
    """
    )

    # orders table
    db.execute(
        """
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        total REAL NOT NULL DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """
    )

    db.execute(
        """
    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        item_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        price_at_order REAL NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(id),
        FOREIGN KEY(item_id) REFERENCES items(id)
    )
    """
    )
    db.commit()

    cur = db.execute("SELECT COUNT(*) AS c FROM items")
    row = cur.fetchone()
    count = row["c"] if row else 0
    if count == 0:
        sample_items = [
            ("Clownfish", 15.00, "clownfish.png", "A classic aquarium fish for saltwater."),
            ("Seaweed", 5.00, "seaweed.png", "Adds natural beauty to your tank, but for saltwater environment only."),
            ("Gravel", 10.00, "gravel.png", "Essential for a healthy aquarium and can serve as a biome for microorganisms that can benefit your aquarium ecosystem."),
            ("Filter", 333.00, "filter.png", "For cleaning and maintaining the aquarium from the food leftovers and waste."),
        ]
        db.executemany(
            "INSERT INTO items (name, price, image, description) VALUES (?, ?, ?, ?)",
            sample_items,
        )
        db.commit()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        if not session.get("is_admin"):
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_uploaded_file(file_storage):
    filename = secure_filename(file_storage.filename)
    unique_name = f"{uuid.uuid4().hex}_{filename}"
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
    file_storage.save(save_path)
    return unique_name


def get_all_items():
    db = get_db()
    cur = db.execute("SELECT * FROM items ORDER BY id ASC")
    rows = cur.fetchall()
    return [row_to_dict(r) for r in rows]


def get_item_by_id(item_id):
    db = get_db()
    cur = db.execute("SELECT * FROM items WHERE id = ?", (item_id,))
    row = cur.fetchone()
    return row_to_dict(row)


@app.before_request
def ensure_db_on_request():
    # Initialize DB on first request (safe: seeds only when empty)
    init_db()


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        flash("You are already logged in.", "info")
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Please provide both username and password.", "warning")
            return render_template("register.html", username=username)

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), 0),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Username is already taken.", "danger")
            return render_template("register.html", username=username)

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    # GET -> show registration form
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    next_page = request.args.get("next") or url_for("index")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Please provide both username and password.", "warning")
            return render_template("login.html")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            session.setdefault("cart", {})
            flash(f"Welcome, {user['username']}!", "success")
            return redirect(next_page)
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))



def ensure_cart():
    if "cart" not in session:
        session["cart"] = {}


@app.route("/cart")
@login_required
def cart():
    ensure_cart()
    cart = session.get("cart", {})
    items = []
    total = 0.0
    for item_id_str, qty in cart.items():
        try:
            item_id = int(item_id_str)
        except ValueError:
            continue
        item = get_item_by_id(item_id)
        if not item:
            continue
        subtotal = item["price"] * qty
        total += subtotal
        items.append({"item": item, "quantity": qty, "subtotal": subtotal})
    return render_template("cart.html", items=items, total=total)


@app.route("/cart/add/<int:item_id>", methods=["POST"])
@login_required
def add_to_cart(item_id):
    ensure_cart()
    item = get_item_by_id(item_id)
    if not item:
        flash("Item not found.", "warning")
        return redirect(request.referrer or url_for("inventory"))
    qty = 1
    try:
        qty = int(request.form.get("qty", 1))
    except (TypeError, ValueError):
        qty = 1
    if qty < 1:
        flash("Quantity must be at least 1.", "warning")
        return redirect(request.referrer or url_for("inventory"))
    cart = session["cart"]
    cart[str(item_id)] = cart.get(str(item_id), 0) + qty
    session["cart"] = cart
    flash(f"Added {item['name']} x{qty} to cart.", "success")
    return redirect(request.referrer or url_for("inventory"))


@app.route("/cart/remove/<int:item_id>", methods=["POST"])
@login_required
def remove_from_cart(item_id):
    ensure_cart()
    cart = session["cart"]
    cart.pop(str(item_id), None)
    session["cart"] = cart
    flash("Item removed from cart.", "info")
    return redirect(url_for("cart"))


@app.route("/cart/update", methods=["POST"])
@login_required
def update_cart():
    ensure_cart()
    cart = session["cart"]
    for key, val in request.form.items():
        if key.startswith("qty_"):
            item_id = key.split("_", 1)[1]
            try:
                q = int(val)
            except ValueError:
                q = 0
            if q <= 0:
                cart.pop(item_id, None)
            else:
                cart[item_id] = q
    session["cart"] = cart
    flash("Cart updated.", "success")
    return redirect(url_for("cart"))


def create_order_from_cart(user_id, cart):
    """Create order and order_items from the session cart (cart is dict of item_id->qty)."""
    if not cart:
        return None
    db = get_db()
    created_at = datetime.utcnow().isoformat()
    total = 0.0
    items_rows = []
    for item_id_str, qty in cart.items():
        try:
            item_id = int(item_id_str)
            qty = int(qty)
        except (ValueError, TypeError):
            continue
        item = get_item_by_id(item_id)
        if not item:
            continue
        price = float(item["price"])
        subtotal = price * qty
        total += subtotal
        items_rows.append((item_id, qty, price))
    cur = db.execute("INSERT INTO orders (user_id, created_at, total) VALUES (?, ?, ?)", (user_id, created_at, total))
    order_id = cur.lastrowid
    for item_id, qty, price in items_rows:
        db.execute("INSERT INTO order_items (order_id, item_id, quantity, price_at_order) VALUES (?, ?, ?, ?)", (order_id, item_id, qty, price))
    db.commit()
    return order_id


@app.route("/checkout", methods=["POST"])
@login_required
def checkout():
    ensure_cart()
    cart = session.get("cart", {})
    if not cart:
        flash("Your cart is empty.", "warning")
        return redirect(url_for("cart"))
    user_id = session.get("user_id")
    order_id = create_order_from_cart(user_id, cart)
    if order_id is None:
        flash("Could not create order.", "danger")
        return redirect(url_for("cart"))
    session["cart"] = {}
    flash(f"Order #{order_id} created successfully.", "success")
    return redirect(url_for("order_detail", order_id=order_id))


@app.route("/orders")
@login_required
def orders():
    db = get_db()
    user_id = session.get("user_id")
    cur = db.execute("SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    orders = [row_to_dict(r) for r in cur.fetchall()]
    return render_template("orders.html", orders=orders)


@app.route("/order/<int:order_id>")
@login_required
def order_detail(order_id):
    db = get_db()
    order_row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not order_row:
        return "Order not found", 404
    order = row_to_dict(order_row)
    if order["user_id"] != session.get("user_id") and not session.get("is_admin"):
        abort(403)
    cur = db.execute(
        "SELECT oi.*, i.name, i.description FROM order_items oi JOIN items i ON oi.item_id = i.id WHERE oi.order_id = ?",
        (order_id,),
    )
    items = [row_to_dict(r) for r in cur.fetchall()]
    return render_template("order_detail.html", order=order, items=items)



@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    """
    Admin-only: delete a user and their orders/order_items.
    Protections:
      - Cannot delete the last remaining admin.
      - Cannot delete yourself via the admin UI (prevents accidental lockout).
    """
    db = get_db()
    user_row = db.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_row:
        flash("User not found.", "warning")
        return redirect(url_for("admin_users"))

    user = row_to_dict(user_row)

    if session.get("user_id") == user["id"]:
        flash("You cannot delete your own account from the admin UI. Log in as another admin to remove this account.", "warning")
        return redirect(url_for("admin_users"))

    if user.get("is_admin"):
        count_row = db.execute("SELECT COUNT(*) AS c FROM users WHERE is_admin = 1").fetchone()
        admin_count = count_row["c"] if count_row else 0
        if admin_count <= 1:
            flash("Cannot delete the last admin user.", "danger")
            return redirect(url_for("admin_users"))

    try:
        order_ids = [r["id"] for r in db.execute("SELECT id FROM orders WHERE user_id = ?", (user["id"],)).fetchall()]
        if order_ids:
            db.executemany("DELETE FROM order_items WHERE order_id = ?", [(oid,) for oid in order_ids])
            db.execute("DELETE FROM orders WHERE user_id = ?", (user["id"],))
        # Finally delete the user
        db.execute("DELETE FROM users WHERE id = ?", (user["id"],))
        db.commit()
    except Exception as e:
        db.rollback()
        flash("An error occurred deleting the user: " + str(e), "danger")
        return redirect(url_for("admin_users"))

    flash(f"User {user.get('username')} deleted.", "success")
    return redirect(url_for("admin_users"))
@app.route("/admin/orders")
@admin_required
def admin_orders():
    db = get_db()
    cur = db.execute("SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id = u.id ORDER BY created_at DESC")
    orders = [row_to_dict(r) for r in cur.fetchall()]
    return render_template("admin_orders.html", orders=orders)


@app.route("/admin/users")
@admin_required
def admin_users():
    db = get_db()
    cur = db.execute("SELECT id, username, password_hash, is_admin FROM users ORDER BY id ASC")
    users = [row_to_dict(r) for r in cur.fetchall()]
    return render_template("admin_users.html", users=users)


@app.route("/admin/user/<int:user_id>/toggle-admin", methods=["POST"])
@admin_required
def admin_toggle_user(user_id):
    """Toggle is_admin for a user. Only accessible to admins."""
    db = get_db()
    user_row = db.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_row:
        flash("User not found.", "warning")
        return redirect(url_for("admin_users"))

    user = row_to_dict(user_row)
    new_flag = 0 if user.get("is_admin") else 1

    if user.get("is_admin"):
        count_row = db.execute("SELECT COUNT(*) AS c FROM users WHERE is_admin = 1").fetchone()
        admin_count = count_row["c"] if count_row else 0
        if admin_count <= 1:
            flash("Cannot demote the last admin user.", "danger")
            return redirect(url_for("admin_users"))

    db.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_flag, user_id))
    db.commit()

    if session.get("user_id") == user_id:
        session["is_admin"] = bool(new_flag)

    action = "promoted to admin" if new_flag else "demoted from admin"
    flash(f"User {user.get('username')} {action}.", "success")
    return redirect(url_for("admin_users"))


@app.route("/")
@login_required
def index():
    items = get_all_items()
    return render_template("index.html", items=items)


@app.route("/product/<int:item_id>")
@login_required
def product_detail(item_id):
    item = get_item_by_id(item_id)
    if not item:
        return "Product not found", 404
    return render_template("product_detail.html", item=item)


@app.route("/inventory")
@login_required
def inventory():
    items = get_all_items()
    return render_template("inventory.html", items=items)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add_item():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price_str = request.form.get("price", "").strip()
        description = request.form.get("description", "").strip()
        image_filename = None
        file = request.files.get("image")
        if file and file.filename and allowed_file(file.filename):
            image_filename = save_uploaded_file(file)
        if price_str:
            try:
                price = float(price_str)
            except ValueError:
                return render_template("add_item.html", error="Invalid price", name=name, description=description)
        else:
            price = 0.0
        db = get_db()
        db.execute(
            "INSERT INTO items (name, price, image, description) VALUES (?, ?, ?, ?)",
            (name, price, image_filename, description),
        )
        db.commit()
        flash("Item added.", "success")
        return redirect(url_for("inventory"))
    return render_template("add_item.html")


@app.route("/edit/<int:item_id>", methods=["GET", "POST"])
@login_required
def edit_item(item_id):
    item = get_item_by_id(item_id)
    if not item:
        return "Item not found", 404
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price_str = request.form.get("price", "").strip()
        description = request.form.get("description", "").strip()
        file = request.files.get("image")
        image_filename = item.get("image")
        if file and file.filename and allowed_file(file.filename):
            image_filename = save_uploaded_file(file)
        if price_str:
            try:
                price = float(price_str)
            except ValueError:
                item = get_item_by_id(item_id)
                return render_template("edit_item.html", item=item, error="Invalid price")
        else:
            price = 0.0
        db = get_db()
        db.execute(
            "UPDATE items SET name = ?, price = ?, image = ?, description = ? WHERE id = ?",
            (name, price, image_filename, description, item_id),
        )
        db.commit()
        flash("Item updated.", "success")
        return redirect(url_for("inventory"))
    return render_template("edit_item.html", item=item)


@app.route("/remove/<int:item_id>", methods=["POST"])
@login_required
def remove_item(item_id):
    db = get_db()
    db.execute("DELETE FROM items WHERE id = ?", (item_id,))
    db.commit()
    # Also remove from any active session carts (best-effort)
    try:
        for key in list(session.get("cart", {}).keys()):
            if key == str(item_id):
                session["cart"].pop(key, None)
    except Exception:
        pass
    flash("Item removed.", "info")
    return redirect(url_for("inventory"))


# ------------------- Debug / helpers -------------------
@app.route("/debug/session")
def debug_session():
    simple_session = {k: v for k, v in session.items() if isinstance(v, (str, int, float, bool, dict, list))}
    return jsonify(simple_session)


# ------------------- CLI helpers -------------------
@app.cli.command("init-db")
def init_db_command():
    """Initialize the database (create tables and seed sample items)."""
    init_db()
    click.echo("Initialized the database at: %s" % DATABASE)


@app.cli.command("create-user")
@click.argument("username")
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
@click.option("--admin", is_flag=True, help="Create the user with admin privileges")
def create_user_command(username, password, admin):
    """Create a user from the command line. Use --admin to make the user an admin."""
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), 1 if admin else 0),
        )
        db.commit()
    except sqlite3.IntegrityError:
        click.echo("Error: username already exists.")
    else:
        click.echo(f"User '{username}' created." + (" (admin)" if admin else ""))


if __name__ == "__main__":
    app.run(debug=True)