import os

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from sqlalchemy import inspect
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    "DATABASE_URL1", "sqlite:///finance.db"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Create Database Tables
class Company(db.Model):
    symbol = db.Column(db.String(250), nullable=False, primary_key=True)
    name = db.Column(db.String(250), nullable=False)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), nullable=False, unique=True)
    hash = db.Column(db.String(250), nullable=False)
    cash = db.Column(db.Float, nullable=False, default=10000.00)


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    symbol = db.Column(db.String(250), nullable=False)
    shares = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    time = db.Column(db.DateTime, nullable=False)


db.create_all()


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session
app.config["SESSION_PERMANENT"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
print(os.environ.get("SECRET_KEY"))
Session(app)

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    # Get user balance
    user = User.query.filter_by(id=user_id).first()
    user = user.__dict__
    print(user["cash"])

    # SUM all shares of user's transactions
    shares = (
        db.session.query(
            Transaction.symbol.label('symbol'),
            db.func.sum(Transaction.shares).label('shares'),
        )
        .filter(Transaction.user_id == user_id)
        .group_by(Transaction.symbol)
        .having(db.func.sum(Transaction.shares) > 0)
        .all()
    )
    print(shares)

    # Check price of each shares and calculate grand total
    total = user["cash"]
    new_shares = []
    print()
    for share in shares:
        company = lookup(share[0])

        new_shares.append(
            {
                "symbol": share[0],
                "shares": share[1],
                "price": company["price"],
                "name": company["name"],
                "total": company["price"] * share[1],
            }
        )

        total += new_shares[-1]["total"]
    print(new_shares)

    return render_template(
        "index.html", shares=new_shares, balance=user["cash"], total=total
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if symbol == "":
            return apology("Invalid Symbol")
        if shares == "" or int(shares) < 1:
            return apology("Invalid Shares")

        company = lookup(symbol)
        if not company:
            return apology("Invalid Symbol")

        shares = int(shares)
        user_id = session["user_id"]
        user = db.session.query(User).filter(User.id == user_id).first()
        if company["price"] * shares > user.cash:
            return apology("Insufficient Fund")

        price = company["price"]
        name = company["name"]
        time = datetime.datetime.now()

        # Update user's cash
        user.cash -= company["price"]
        db.session.commit()

        # Update company table for new company
        company = db.session.query(Company).filter(Company.symbol == symbol).first()
        if not company:
            new_company = Company(symbol=symbol, name=name)
            db.session.add(new_company)
            db.session.commit()

        # Insert new transaction
        new_transaction = Transaction(
            user_id=user_id, symbol=symbol, shares=shares, price=price, time=time
        )
        db.session.add(new_transaction)
        db.session.commit()

        flash("Bought!")
        return redirect("/")

    # Method: "GET"
    if request.args.get("symbol"):
        company = lookup(request.args.get("symbol"))
        if not company:
            return apology("Invalid Symbol")
        return render_template("buy.html", symbol=company["symbol"])
    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.session.query(Transaction).filter(
        Transaction.user_id == session["user_id"]
    )
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = (
            db.session.query(User)
            .filter(User.username == request.form.get("username"))
            .first()
        )
        print(rows)

        # Ensure username exists and password is correct
        if not rows or not check_password_hash(rows.hash, request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows.id

        # Redirect user to home page
        flash("Logged In!")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if symbol == "":
            return apology("Invalid Symbol")

        company = lookup(symbol)
        if not company:
            return apology("Invalid Symbol")

        return jsonify(company)
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirmation")

        # Validate user input
        if username == "":
            return apology("Username cannot be blank")
        if password == "":
            return apology("Password must be 8 chracters or more")
        if password != confirm:
            return apology("Password didn't match")

        user = db.session.query(User).filter(User.username == username).first()

        if user:
            return apology("Username already taken")

        # Hash password so it can't be cracked by other people
        hash_password = generate_password_hash(password)
        new_user = User(username=username, hash=hash_password)
        db.session.add(new_user)
        db.session.commit()
        user_id = new_user.id

        # Remember which user has logged in
        session["user_id"] = user_id
        print('\nregister', '\n', session, '\n')

        # Redirect to home page
        flash("Registered!")
        return redirect("/")

    # Method: "GET"
    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    user_id = session["user_id"]

    # Stocks that the user currently has
    stocks = (
        db.session.query(
            Transaction.symbol, db.func.sum(Transaction.shares).label("shares")
        )
        .filter(Transaction.user_id == user_id)
        .group_by(Transaction.symbol)
        .having(db.func.sum(Transaction.shares) > 0)
    )
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if symbol == "":
            return apology("Invalid Symbol")
        if shares == "" or int(shares) < 1:
            return apology("Invalid Shares")

        company = lookup(symbol)
        if not company:
            return apology("Invalid Symbol")

        # Check if the user has the stocks
        shares = int(shares)
        current_stock = [stock for stock in stocks if stock[0] == symbol]
        if len(current_stock) != 1:
            return apology("Insufficient shares")
        if current_stock[0][1] < shares:
            return apology("Insufficient shares")

        user = db.session.query(User).filter(User.id == user_id).first()
        time = datetime.datetime.now()

        # Update user's cash
        user.cash += company["price"] * shares
        db.session.commit()

        # Insert new transaction
        new_transaction = Transaction(
            user_id=user_id,
            symbol=symbol,
            shares=-shares,
            price=company["price"],
            time=time,
        )
        db.session.add(new_transaction)
        db.session.commit()
        flash("Sold!")
        return redirect("/")

    # Method: "GET"
    return render_template("sell.html", symbols=stocks)


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """Change Password"""
    if request.method == "POST":
        curr_input = request.form.get("current")
        new_pass = request.form.get("new")
        confirm_pass = request.form.get("confirm")

        # Validate user input
        curr_pass = db.execute(
            "SELECT hash FROM users WHERE id = ?", session["user_id"]
        )

        if not check_password_hash(curr_pass[0]["hash"], curr_input):
            return apology("Current password didn't match")
        if new_pass == "":
            return apology("Password must be 8 chracters or more")
        if new_pass != confirm_pass:
            return apology("New password didn't match")

        db.execute(
            "UPDATE users SET hash = ? WHERE id = ?",
            generate_password_hash(new_pass),
            session["user_id"],
        )
        return redirect("/")

    # Method: "GET"
    return render_template("change.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
