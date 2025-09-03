from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from bson.binary import Binary
from pymongo.errors import DuplicateKeyError
import bcrypt
import os
import certifi
from bson.objectid import ObjectId

app = Flask(__name__)

# ==== SECURITY (change in production) ====
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# ==== MongoDB Atlas connection ====
MONGO_URI = "mongodb+srv://piyushkoli2605_db_user:3GAQOhELvoQT7gup@cluster0.o6g3qrr.mongodb.net/lms_db?retryWrites=true&w=majority&appName=Cluster0"

client = MongoClient(
    MONGO_URI,
    tls=True,
    tlsCAFile=certifi.where(),
    serverSelectionTimeoutMS=5000
)

db = client["lms_db"]
users_collection = db["users"]

# Ensure unique emails
users_collection.create_index("email", unique=True)

# ==== Seed Admins (Werkzeug hashes; idempotent) ====
seed_admins = [
    {"name": "Admin-Piyush", "email": "piyush@syntaxsyndicate.com", "password": "piyush123", "role": "admin"},
    {"name": "Admin-Adinath", "email": "adinath@syntaxsyndicate.com", "password": "adinath123", "role": "admin"}
]
for a in seed_admins:
    if not users_collection.find_one({"email": a["email"]}):
        users_collection.insert_one({
            "name": a["name"],
            "email": a["email"].lower().strip(),
            "password": generate_password_hash(a["password"]),  # store Werkzeug string hash
            "role": a["role"]
        })

# ==== Helpers ====
def verify_password(plain: str, stored_hash):
    """
    Backward-compatible password verify:
    - If stored_hash is Werkzeug string -> use check_password_hash
    - If stored_hash is bytes/Binary (old bcrypt) -> use bcrypt.checkpw
    """
    if isinstance(stored_hash, (bytes, Binary)):
        # Bcrypt branch
        hashed_bytes = bytes(stored_hash)  # Binary -> bytes
        return bcrypt.checkpw(plain.encode("utf-8"), hashed_bytes)
    if isinstance(stored_hash, str):
        # Werkzeug branch
        return check_password_hash(stored_hash, plain)
    # Unknown type
    return False

# ==== Routes ====
@app.route("/")
def landing():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").lower().strip()
        password = request.form.get("password") or ""

        if not name or not email or not password:
            flash("All fields are required.", "warning")
            return redirect(url_for("register"))

        try:
            users_collection.insert_one({
                "name": name,
                "email": email,
                "password": generate_password_hash(password),  # Werkzeug string hash
                "role": "user"
            })
        except DuplicateKeyError:
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for("login"))

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").lower().strip()
        password = request.form.get("password") or ""

        user = users_collection.find_one({"email": email})
        if user and verify_password(password, user.get("password")):
            session["user_id"] = str(user["_id"])
            session["role"] = user.get("role", "user")
            flash("Login successful!", "success")
            return redirect(url_for("admin_dashboard" if session["role"] == "admin" else "user_dashboard"))

        flash("Invalid email or password.", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/user/dashboard")
def user_dashboard():
    if "user_id" not in session or session.get("role") != "user":
        flash("Please log in as a user to continue.", "warning")
        return redirect(url_for("login"))

    user = users_collection.find_one(
        {"_id": ObjectId(session["user_id"])},
        {"password": 0}  # don't send hash to template
    )
    if not user:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    return render_template("user_dash.html", user=user)



@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/edit_profile", methods=["POST"])
def edit_profile():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").lower().strip()
    password = request.form.get("password", "")

    user_id = ObjectId(session["user_id"])

    # ✅ check if the email exists for someone else
    existing_user = users_collection.find_one({
        "email": email,
        "_id": {"$ne": user_id}
    })

    if existing_user:
        flash("This email is already registered. Please use a different one.", "danger")
        return redirect(url_for("user_dashboard"))

    update_data = {"name": name, "email": email}
    if password:
        update_data["password"] = generate_password_hash(password)

    users_collection.update_one(
        {"_id": user_id},
        {"$set": update_data}
    )

    flash("Profile updated successfully!", "success")
    return redirect(url_for("user_dashboard"))

@app.route("/browse_courses")
def browse_courses():
    if "user_id" not in session or session.get("role") != "user":
        flash("Please log in as a user to continue.", "warning")
        return redirect(url_for("login"))

    # Fetch all courses from DB
    courses = list(db["courses"].find({}, {"_id": 0}))  

    return render_template("browse_courses.html", courses=courses)


@app.route("/enroll/<course_id>", methods=["POST"])
def enroll_course(course_id):
    if "user_id" not in session:
        flash("Please log in to enroll.", "warning")
        return redirect(url_for("login"))

    course = db["courses"].find_one({"_id": ObjectId(course_id)})
    if not course:
        flash("Course not found.", "danger")
        return redirect(url_for("browse_courses"))

    # Add course to user’s enrolled list if not already
    users_collection.update_one(
        {"_id": ObjectId(session["user_id"])},
        {"$addToSet": {"courses": {
            "_id": course["_id"],
            "title": course["title"],
            "description": course.get("description", ""),
            "progress": 0  # start at 0%
        }}}
    )

    flash(f"You have successfully enrolled in {course['title']}!", "success")
    return redirect(url_for("user_dashboard"))


# ----------------------
# Admin Dashboard Routes
# ----------------------
@app.route("/admin_dashboard")
def admin_dashboard():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    user = users_collection.find_one({"_id": ObjectId(session["user_id"])})
    if not user or user.get("role") != "admin":
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for("user_dashboard"))

    return render_template("admin_dash.html", title="Admin Dashboard")


@app.route("/admin_users")
def admin_users():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    user = users_collection.find_one({"_id": ObjectId(session["user_id"])})
    if not user or user.get("role") != "admin":
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for("user_dashboard"))

    users = list(users_collection.find({}, {"password": 0}))  # hide password hash
    return render_template("admin_users.html", users=users, title="Registered Users")


@app.route("/admin_courses")
def admin_courses():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    user = users_collection.find_one({"_id": ObjectId(session["user_id"])})
    if not user or user.get("role") != "admin":
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for("user_dashboard"))

    # Example: fetch all course submissions
    courses = list(courses_collection.find())
    return render_template("admin_courses.html", courses=courses, title="Course Submissions")


@app.route('/admin/delete_user/<user_id>')
def delete_user(user_id):
    # Only admins can delete
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))

    users_collection.delete_one({"_id": ObjectId(user_id)})
    flash("User deleted successfully.", "success")
    return redirect(url_for('admin_users'))

# ==== Run ====
if __name__ == "__main__":
    app.run(debug=True)
