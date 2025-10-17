from datetime import datetime

from bson.objectid import ObjectId
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, session, url_for
from flask_mail import Mail, Message
from flask_pymongo import PyMongo
from flask_wtf import CSRFProtect, FlaskForm
from flask_wtf.csrf import generate_csrf
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import BooleanField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Email

from config import Config


load_dotenv()


app = Flask(__name__)
app.config.from_object(Config)


csrf = CSRFProtect(app)
mongo = PyMongo(app)
mail = Mail(app)


class RiderForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    id_number = StringField("ID", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    is_rider = BooleanField("Sign up as rider", default=True)
    submit = SubmitField("Create profile")


class RideRequestForm(FlaskForm):
    passenger_name = StringField("Name", validators=[DataRequired()])
    passenger_email = StringField("Email", validators=[DataRequired(), Email()])
    pickup = SelectField(
        "Pickup",
        choices=[
            ("UIU 1st gate", "UIU 1st gate"),
            ("Kuril highway", "Kuril highway"),
            ("Bashundhora bitumin gate", "Bashundhora bitumin gate"),
            ("Noton Bazar", "Noton Bazar"),
        ],
        validators=[DataRequired()],
    )
    destination = StringField("Destination", validators=[DataRequired()])
    submit = SubmitField("Send Request")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log in")


def deliver(message):
    try:
        mail.send(message)
    except Exception:
        pass


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": generate_csrf}


def get_request_document(request_id):
    try:
        return mongo.db.requests.find_one({"_id": ObjectId(request_id)})
    except Exception:
        return None


def update_request_status(ride, status, rider_account=None):
    if not ride:
        return None
    changed = ride.get("status") != status
    if changed:
        update_fields = {
            "status": status,
            "updated_at": datetime.utcnow(),
        }
        if status == "accepted":
            accepted_payload = {}
            if rider_account:
                accepted_payload = {
                    "id": str(rider_account.get("_id")),
                    "name": rider_account.get("name"),
                    "email": rider_account.get("email"),
                }
            update_fields.update(
                {
                    "accepted_by": accepted_payload or ride.get("accepted_by"),
                    "accepted_at": datetime.utcnow(),
                }
            )
        else:
            update_fields.update({
                "accepted_by": None,
                "accepted_at": None,
            })
        mongo.db.requests.update_one(
            {"_id": ride["_id"]},
            {"$set": update_fields},
        )
        updated = mongo.db.requests.find_one({"_id": ride["_id"]})
    else:
        updated = ride
    subject = None
    if status == "accepted":
        subject = "Mini Ride: a rider is on the way"
    elif status == "declined":
        subject = "Mini Ride: request update"
    if subject and changed and updated:
        passenger_message = Message(
            subject=subject,
            recipients=[updated["passenger_email"]],
            html=render_template(
                "emails/passenger_confirm.html",
                ride=updated,
                dashboard_link=url_for("dashboard", _external=True),
            ),
        )
        deliver(passenger_message)
    return updated


@app.route("/")
def home():
    return render_template("landing.html", datetime=datetime)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = RiderForm()
    if form.validate_on_submit():
        collection_name = "riders" if form.is_rider.data else "users"
        if mongo.db[collection_name].find_one({"email": form.email.data}):
            form.email.errors.append("Email already registered")
            return render_template("signup.html", form=form)
        rider = {
            "name": form.name.data,
            "id_number": form.id_number.data,
            "email": form.email.data,
            "password": generate_password_hash(form.password.data),
            "is_rider": form.is_rider.data,
            "created_at": datetime.utcnow(),
        }
        result = mongo.db[collection_name].insert_one(rider)
        session["account_id"] = str(result.inserted_id)
        session["account_collection"] = collection_name
        return redirect(url_for("dashboard", state="signup"))
    return render_template("signup.html", form=form)


@app.route("/request", methods=["GET", "POST"])
def request_ride():
    form = RideRequestForm()
    if form.validate_on_submit():
        ride = {
            "passenger_name": form.passenger_name.data,
            "passenger_email": form.passenger_email.data,
            "pickup": form.pickup.data,
            "destination": form.destination.data,
            "status": "pending",
            "created_at": datetime.utcnow(),
        }
        ride_id = mongo.db.requests.insert_one(ride).inserted_id
        ride["_id"] = ride_id
        riders = list(mongo.db.riders.find())
        for recipient in riders:
            message = Message(
                subject="Mini Ride: new passenger request",
                recipients=[recipient["email"]],
                html=render_template(
                    "emails/rider_notify.html",
                    rider=recipient,
                    ride=ride,
                    review_link=url_for("review_request", request_id=str(ride_id), _external=True),
                    approve_link=url_for(
                        "confirm_request",
                        request_id=str(ride_id),
                        rider_id=str(recipient.get("_id")),
                        _external=True,
                    ),
                ),
            )
            deliver(message)
        passenger_message = Message(
            subject="Mini Ride: request received",
            recipients=[ride["passenger_email"]],
            html=render_template(
                "emails/passenger_confirm.html",
                ride=ride,
            ),
        )
        deliver(passenger_message)
        account_collection = session.get("account_collection")
        if account_collection in {"users", "riders"} and session.get("account_id"):
            session["toast_message"] = "Ride request sent. We'll notify riders now."
            tab_target = "requests" if account_collection == "riders" else "list"
            return redirect(url_for("dashboard", tab=tab_target, state="request"))
        return render_template(
            "confirm.html",
            title="Ride requested",
            message="We pinged nearby riders. Watch your inbox for updates.",
        )
    return render_template("request.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        collection_name = "riders"
        account = mongo.db.riders.find_one({"email": email})
        if not account:
            collection_name = "users"
            account = mongo.db.users.find_one({"email": email})
        if not account or not account.get("password") or not check_password_hash(account["password"], form.password.data):
            form.email.errors.append("Invalid email or password")
            return render_template("login.html", form=form)
        session["account_id"] = str(account["_id"])
        session["account_collection"] = collection_name
        return redirect(url_for("dashboard", state="login"))
    return render_template("login.html", form=form)


@app.route("/dashboard")
def dashboard():
    account_id = session.get("account_id")
    collection_name = session.get("account_collection")
    if not account_id or not collection_name:
        return redirect(url_for("login"))
    try:
        account = mongo.db[collection_name].find_one({"_id": ObjectId(account_id)})
    except Exception:
        account = None
    if not account:
        session.clear()
        return redirect(url_for("login"))
    state = request.args.get("state")
    recent_requests = []
    try:
        cursor = mongo.db.requests.find().sort("created_at", -1).limit(5)
        for item in cursor:
            item_copy = dict(item)
            item_copy["id_str"] = str(item_copy.pop("_id", ""))
            recent_requests.append(item_copy)
    except Exception:
        recent_requests = []
    pending_count = mongo.db.requests.count_documents({"status": "pending"})
    accepted_count = mongo.db.requests.count_documents({"status": "accepted"})
    total_riders = mongo.db.riders.count_documents({})
    total_profiles = mongo.db.users.count_documents({})
    member_requests = []
    if collection_name == "users":
        try:
            cursor = (
                mongo.db.requests.find({"passenger_email": account.get("email")})
                .sort("created_at", -1)
                .limit(10)
            )
            for item in cursor:
                item_copy = dict(item)
                item_copy["id_str"] = str(item_copy.pop("_id", ""))
                member_requests.append(item_copy)
        except Exception:
            member_requests = []
    request_form = RideRequestForm()
    if collection_name in {"users", "riders"}:
        request_form.passenger_name.data = account.get("passenger_name", account.get("name", ""))
        request_form.passenger_email.data = account.get("email", "")
    if collection_name == "riders":
        role_key = "rider"
        hero_message = "Inbox alerts keep you rolling."
        cta_label = "Review passenger requests"
        cta_link = url_for("home")
        rider_requests = recent_requests
    else:
        role_key = "member"
        hero_message = "Share passenger tools with your network."
        cta_label = "Create passenger request"
        cta_link = url_for("request_ride")
        rider_requests = []
    default_tab = "requests" if role_key == "rider" else "list"
    active_tab = request.args.get("tab") or default_tab
    toast_message = session.pop("toast_message", None)
    return render_template(
        "dashboard.html",
        account=account,
        role_key=role_key,
        hero_message=hero_message,
        cta_label=cta_label,
        cta_link=cta_link,
        state=state,
        pending_count=pending_count,
        accepted_count=accepted_count,
        recent_requests=recent_requests,
        total_riders=total_riders,
        total_profiles=total_profiles,
        member_requests=member_requests,
        request_form=request_form,
        rider_requests=rider_requests,
        active_tab=active_tab,
        toast_message=toast_message,
    )


@app.route("/requests/<request_id>/approve", methods=["POST"])
def approve_request(request_id):
    if session.get("account_collection") != "riders":
        return redirect(url_for("login"))
    ride = get_request_document(request_id)
    if not ride:
        session["toast_message"] = "Ride request is no longer available."
        return redirect(url_for("dashboard", tab="requests"))
    rider_account = None
    account_id = session.get("account_id")
    if account_id:
        try:
            rider_account = mongo.db.riders.find_one({"_id": ObjectId(account_id)})
        except Exception:
            rider_account = None
    updated = update_request_status(ride, "accepted", rider_account=rider_account)
    if updated:
        session["toast_message"] = f"{updated['passenger_name']} has been notified."
    else:
        session["toast_message"] = "Unable to update ride request."
    return redirect(url_for("dashboard", tab="requests", state="approve"))


@app.route("/requests/<request_id>/reject", methods=["POST"])
def reject_request(request_id):
    if session.get("account_collection") != "riders":
        return redirect(url_for("login"))
    ride = get_request_document(request_id)
    if not ride:
        session["toast_message"] = "Ride request is no longer available."
        return redirect(url_for("dashboard", tab="requests"))
    updated = update_request_status(ride, "declined")
    if updated:
        session["toast_message"] = f"Marked {updated['passenger_name']}'s request as declined."
    else:
        session["toast_message"] = "Unable to update ride request."
    return redirect(url_for("dashboard", tab="requests", state="reject"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/rider/<request_id>")
def review_request(request_id):
    try:
        ride = mongo.db.requests.find_one({"_id": ObjectId(request_id)})
    except Exception:
        ride = None
    if not ride:
        return render_template(
            "confirm.html",
            title="Ride not found",
            message="This request is no longer available.",
        )
    return render_template("rider.html", ride=ride, ride_id=str(ride["_id"]))


@app.route("/confirm/<request_id>")
def confirm_request(request_id):
    ride = get_request_document(request_id)
    if not ride:
        return render_template(
            "confirm.html",
            title="Ride not found",
            message="This request is no longer available.",
        )
    rider_account = None
    rider_id = request.args.get("rider_id")
    if rider_id:
        try:
            rider_account = mongo.db.riders.find_one({"_id": ObjectId(rider_id)})
        except Exception:
            rider_account = None
    ride = update_request_status(ride, "accepted", rider_account=rider_account)
    return render_template(
        "confirm.html",
        title="Ride accepted",
        message=f"{ride['passenger_name']} has been notified.",
    )


if __name__ == "__main__":
    app.run(debug=True)
