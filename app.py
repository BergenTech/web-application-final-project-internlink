from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin
from flask_login import login_user, current_user, logout_user, login_required

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("home.html")

if __name__ == "__main__":
    app.run(debug=True)