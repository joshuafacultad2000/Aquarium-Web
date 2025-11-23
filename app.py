import os
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

# Database file (for users)
DATABASE = os.path.join(app.root_path, "database.db")


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    db.execute(
        """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    """
    )
    db.commit()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


# Simple login_required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)

    return decorated_function


# Configure upload folder
UPLOAD_FOLDER = os.path.join("static", "images")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Allowed extensions
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# Sample data - replace with a database if you want persistent items
aquarium_items = [
    {"id": 1, "name": "Clownfish", "price": 15.00, "image": "clownfish.png", "description": "A classic aquarium fish."},
    {"id": 2, "name": "Seaweed", "price": 5.00, "image": "seaweed.png", "description": "Adds natural beauty to your tank."},
    {"id": 3, "name": "Gravel", "price": 10.00, "image": "gravel.png", "description": "Essential for a healthy aquarium."},
    {"id": 4, "name": "Filter", "price": 333.0, "image": "filter.png", "description": "A less common but exciting aquarium addition."},
]


def get_item_by_id(item_id):
    return next((item for item in aquarium_items if item["id"] == item_id), None)


# --- Authentication routes ---


@app.before_request
def ensure_db():
    init_db()


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Please provide both username and password.", "warning")
            return render_template("register.html", username=username)

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Username is already taken.", "danger")
            return render_template("register.html", username=username)

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))
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
            # ensure a cart exists for this session
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


# --- Cart routes (stored in session) ---


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


@app.route("/cart/add/<int:item_id>", methods=["POST", "GET"])
@login_required
def add_to_cart(item_id):
    ensure_cart()
    cart = session["cart"]
    cart[str(item_id)] = cart.get(str(item_id), 0) + 1
    session["cart"] = cart
    flash("Item added to cart.", "success")
    # If request came from product detail, go back there; otherwise inventory
    return redirect(request.referrer or url_for("inventory"))


@app.route("/cart/remove/<int:item_id>", methods=["POST", "GET"])
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


# --- Shop routes (require login) ---


@app.route("/")
@login_required
def index():
    return render_template("index.html", items=aquarium_items)


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
    return render_template("inventory.html", items=aquarium_items)


# Add/edit/remove still available, protected for logged-in users
@app.route("/add", methods=["GET", "POST"])
@login_required
def add_item():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price_str = request.form.get("price", "").strip()
        description = request.form.get("description", "").strip()
        image_filename = "default.svg"

        file = request.files.get("image")
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(save_path)
            image_filename = filename

        if price_str:
            try:
                price = float(price_str)
            except ValueError:
                return render_template("add_item.html", error="Invalid price", name=name, description=description)
        else:
            price = 0.0

        next_id = max((item["id"] for item in aquarium_items), default=0) + 1
        new_item = {"id": next_id, "name": name, "price": price, "image": image_filename, "description": description}
        aquarium_items.append(new_item)
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
        item["name"] = request.form.get("name", "").strip()
        price_str = request.form.get("price", "").strip()
        item["description"] = request.form.get("description", "").strip()
        file = request.files.get("image")
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(save_path)
            item["image"] = filename
        if price_str:
            try:
                item["price"] = float(price_str)
            except ValueError:
                return render_template("edit_item.html", item=item, error="Invalid price")
        else:
            item["price"] = 0.0
        flash("Item updated.", "success")
        return redirect(url_for("inventory"))
    return render_template("edit_item.html", item=item)


@app.route("/remove/<int:item_id>", methods=["POST", "GET"])
@login_required
def remove_item(item_id):
    global aquarium_items
    aquarium_items = [item for item in aquarium_items if item["id"] != item_id]
    flash("Item removed.", "info")
    return redirect(url_for("inventory"))


# Debug helper to see session + cart
@app.route("/debug/session")
def debug_session():
    return jsonify(dict(session))


if __name__ == "__main__":
    app.run(debug=True)