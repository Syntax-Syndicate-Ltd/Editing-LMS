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
import datetime

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
courses_collection = db["courses"]
enrollments_collection = db["enrollments"]


from werkzeug.utils import secure_filename

# New collection for requests
enrollment_requests = db["enrollment_requests"]


# Ensure unique emails
users_collection.create_index("email", unique=True)


UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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
    flash("Logged out successfully!", "success")
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
    user_id = str(session.get("user_id")) if "user_id" in session else None

    courses = list(courses_collection.find())
    for c in courses:
        c["_id"] = str(c["_id"])

    user_enrollments = {}
    if user_id:
        requests = enrollment_requests.find({"user_id": user_id})
        for r in requests:
            # Only include relevant statuses
            if r.get("status") in ["pending_admin_approval", "approved", "rejected"]:
                user_enrollments[str(r["course_id"])] = r

    return render_template(
        "browse_courses.html",
        courses=courses,
        user_enrollments=user_enrollments
    )


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
    return render_template("admin_course_submissions.html", courses=courses, title="Course Submissions")


@app.route('/admin/delete_user/<user_id>')
def delete_user(user_id):
    # Only admins can delete
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))

    users_collection.delete_one({"_id": ObjectId(user_id)})
    flash("User deleted successfully.", "success")
    return redirect(url_for('admin_users'))

@app.route("/admin/manage_courses", methods=["GET", "POST"])
def admin_manage_courses():
    if request.method == "POST":
        course_name = request.form.get("course_name")
        description = request.form.get("description")

        if not course_name:
            flash("Course name is required", "danger")
        else:
            courses_collection.insert_one({
                "name": course_name,
                "description": description,
                "weeks": [],  # Empty weeks by default
                "assessments": []  # Empty assessments by default
            })
            flash("Course added successfully!", "success")
        return redirect(url_for("admin_manage_courses"))

    courses = list(courses_collection.find())
    return render_template("admin_manage_courses.html", courses=courses)



@app.route("/admin/course_enrollments")
def admin_course_enrollments():
    enrollments = list(enrollment_requests.find())
    
    # Convert ObjectId to string for Jinja
    for e in enrollments:
        e["_id"] = str(e["_id"])
        # Fix backslashes in screenshot path
        if "screenshot_path" in e and e["screenshot_path"]:
            e["screenshot_path"] = e["screenshot_path"].replace("\\", "/")
    
    return render_template(
        "admin_course_enrollments.html",
        enrollments=enrollments,
        title="Course Enrollments"
    )

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/request_enrollment/<course_id>", methods=["GET", "POST"])
def request_enrollment(course_id):
    if "user_id" not in session or session.get("role") != "user":
        flash("Please login!", "danger")
        return redirect(url_for("login"))

    user_id = str(session["user_id"])
    course = courses_collection.find_one({"_id": ObjectId(course_id)})
    user = users_collection.find_one({"_id": ObjectId(user_id)})

    if not course:
        flash("Course not found!", "danger")
        return redirect(url_for("browse_courses"))

    if request.method == "POST":
        if "screenshot" not in request.files:
            flash("No screenshot uploaded!", "danger")
            return redirect(request.url)

        file = request.files["screenshot"]
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            # Save request in DB
            enrollment_requests.insert_one({
                "course_id": str(course["_id"]),
                "course_name": course["name"],
                "user_id": user_id,
                "user_name": user["name"],
                "user_email": user["email"],
                "screenshot_path": filepath,
                "status": "pending_admin_approval",
                "created_at": datetime.datetime.utcnow()
            })

            flash("Enrollment request submitted! Waiting for admin approval.", "info")
            return redirect(url_for("enrollment_requested"))
        else:
            flash("Invalid file type! Only JPG/PNG allowed.", "danger")

    return render_template("enrollment_form.html", course=course, user=user)


@app.route("/enrollment_requested")
def enrollment_requested():
    if "user_id" not in session:
        flash("Please login first!", "danger")
        return redirect(url_for("login"))

    requests = list(enrollment_requests.find({
        "user_id": str(session["user_id"])
    }).sort("created_at", -1))

    return render_template("enrollment_requested.html", enrollments=requests)

@app.route("/admin/approve_enrollment/<enrollment_id>", methods=["POST"])
def approve_enrollment(enrollment_id):
    enrollment_requests.update_one(
        {"_id": ObjectId(enrollment_id)},
        {"$set": {"status": "approved"}}
    )
    flash("Enrollment approved!", "success")
    return redirect(url_for("admin_course_enrollments"))

@app.route("/admin/reject_enrollment/<enrollment_id>", methods=["POST"])
def reject_enrollment(enrollment_id):
    enrollment_requests.update_one(
        {"_id": ObjectId(enrollment_id)},
        {"$set": {"status": "rejected"}}
    )
    flash("Enrollment rejected!", "danger")
    return redirect(url_for("admin_course_enrollments"))


# --------------- Course Dashboard ---------------
@app.route("/admin/course/<course_id>/dashboard", methods=["GET", "POST"])
def course_dashboard(course_id):
    course = courses_collection.find_one({"_id": ObjectId(course_id)})
    if not course:
        flash("Course not found", "danger")
        return redirect(url_for("admin_manage_courses"))

    if request.method == "POST":
        action = request.form.get("action")

        # ---------------- Add or Update Week ----------------
        if action == "add_week":
            week_title = request.form.get("week_title")
            courses_collection.update_one(
                {"_id": ObjectId(course_id)},
                {"$push": {"weeks": {"title": week_title, "content": []}}}
            )
            flash("Week added successfully!", "success")

        elif action == "update_week":
            week_index = int(request.form.get("week_index"))
            week_title = request.form.get("week_title")
            courses_collection.update_one(
                {"_id": ObjectId(course_id)},
                {"$set": {f"weeks.{week_index}.title": week_title}}
            )
            flash("Week updated successfully!", "success")

        elif action == "delete_week":
            week_index = int(request.form.get("week_index"))
            courses_collection.update_one(
                {"_id": ObjectId(course_id)},
                {"$unset": {f"weeks.{week_index}": 1}}
            )
            courses_collection.update_one(
                {"_id": ObjectId(course_id)},
                {"$pull": {"weeks": None}}
            )
            flash("Week deleted successfully!", "success")

        # ---------------- Add or Update Content ----------------
        elif action == "add_content":
            week_index = int(request.form.get("week_index"))
            content_type = request.form.get("content_type")
            title = request.form.get("content_title")
            url = request.form.get("content_url")

            # NEW: embed link support for videos
            embed_link = None
            if content_type == "video":
                embed_link = request.form.get("content_embed")

            content_data = {
                "type": content_type,
                "title": title,
                "url": url
            }
            if embed_link:
                content_data["embed"] = embed_link

            courses_collection.update_one(
                {"_id": ObjectId(course_id)},
                {"$push": {f"weeks.{week_index}.content": content_data}}
            )
            flash("Content added successfully!", "success")

        elif action == "delete_content":
            week_index = int(request.form.get("week_index"))
            content_index = int(request.form.get("content_index"))

            # remove specific content
            courses_collection.update_one(
                {"_id": ObjectId(course_id)},
                {"$unset": {f"weeks.{week_index}.content.{content_index}": 1}}
            )
            courses_collection.update_one(
                {"_id": ObjectId(course_id)},
                {"$pull": {f"weeks.{week_index}.content": None}}
            )
            flash("Content deleted!", "success")

        # ---------------- Add or Update Assessment ----------------
        elif action == "add_assessment":
            title = request.form.get("assessment_title")
            desc = request.form.get("assessment_desc")
            courses_collection.update_one(
                {"_id": ObjectId(course_id)},
                {"$push": {"assessments": {
                    "title": title,
                    "description": desc,
                    "questions": []
                }}}
            )
            flash("Assessment created!", "success")

        elif action == "update_assessment":
            assessment_index = int(request.form.get("assessment_index"))
            title = request.form.get("assessment_title")
            desc = request.form.get("assessment_desc")

            update_data = {}
            if title is not None:
                update_data[f"assessments.{assessment_index}.title"] = title
            if desc is not None:
                update_data[f"assessments.{assessment_index}.description"] = desc

            if update_data:
                courses_collection.update_one(
                    {"_id": ObjectId(course_id)},
                    {"$set": update_data}
                )
                flash("Assessment updated!", "success")


        elif action == "add_question":
            assessment_index = int(request.form.get("assessment_index"))
            question_text = request.form.get("question_text")
            options_raw = request.form.get("options")  # single input field

            # Convert CSV string into a list
            if options_raw:
                options = [opt.strip() for opt in options_raw.split(",")]
            else:
                options = []

            try:
                correct = int(request.form.get("correct"))
            except (TypeError, ValueError):
                correct = -1  # fallback if not provided

            courses_collection.update_one(
                {"_id": ObjectId(course_id)},
                {"$push": {
                    f"assessments.{assessment_index}.questions": {
                        "question": question_text,
                        "options": options,
                        "correct": correct
                    }
                }}
            )
            flash("Question added!", "success")

        elif action == "delete_question":
            assessment_index = int(request.form.get("assessment_index"))
            question_index = int(request.form.get("question_index"))

            # Step 1: Unset the specific question
            courses_collection.update_one(
                {"_id": ObjectId(course_id)},
                {"$unset": {f"assessments.{assessment_index}.questions.{question_index}": 1}}
            )

            # Step 2: Pull out the null left behind
            courses_collection.update_one(
                {"_id": ObjectId(course_id)},
                {"$pull": {f"assessments.{assessment_index}.questions": None}}
            )

            flash("Question deleted!", "success")

        elif action == "update_question":
            assessment_index = int(request.form.get("assessment_index"))
            question_index = int(request.form.get("question_index"))

            question_text = request.form.get("question_text")
            options_raw = request.form.get("options")  # CSV string: "opt1, opt2, opt3"
            correct = request.form.get("correct")

            # Normalize options
            if options_raw:
                options = [opt.strip() for opt in options_raw.split(",")]
            else:
                options = []

            try:
                correct = int(correct)
            except (TypeError, ValueError):
                correct = -1

            update_data = {}
            if question_text:
                update_data[f"assessments.{assessment_index}.questions.{question_index}.question"] = question_text
            if options:
                update_data[f"assessments.{assessment_index}.questions.{question_index}.options"] = options
            if correct is not None:
                update_data[f"assessments.{assessment_index}.questions.{question_index}.correct"] = correct

            if update_data:
                courses_collection.update_one(
                    {"_id": ObjectId(course_id)},
                    {"$set": update_data}
                )
                flash("Question updated!", "success")


        elif action == "delete_assessment":
            assessment_index = int(request.form.get("assessment_index"))
            courses_collection.update_one(
                {"_id": ObjectId(course_id)},
                {"$unset": {f"assessments.{assessment_index}": 1}}
            )
            courses_collection.update_one(
                {"_id": ObjectId(course_id)},
                {"$pull": {"assessments": None}}
            )
            flash("Assessment deleted!", "success")

        elif action == "update_content":
            week_index = int(request.form.get("week_index"))
            content_index = int(request.form.get("content_index"))
            title = request.form.get("content_title")
            url = request.form.get("content_url")
            embed = request.form.get("content_embed")

            update_data = {
        f"weeks.{week_index}.content.{content_index}.title": title,
        f"weeks.{week_index}.content.{content_index}.url": url,
        f"weeks.{week_index}.content.{content_index}.embed": embed
    }

            courses_collection.update_one(
            {"_id": ObjectId(course_id)},
            {"$set": update_data}
    )
            flash("Content updated successfully!", "success")

        return redirect(url_for("course_dashboard", course_id=course_id))

    return render_template("course_dashboard.html", course=course)



# ==== Run ====
if __name__ == "__main__":
    app.run(debug=True)
