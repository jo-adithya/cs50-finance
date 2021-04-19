import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
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


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    # Get user balance
    user = db.execute("SELECT cash FROM users WHERE id = ?", user_id)

    # SUM all shares of user's transactions
    shares = db.execute("SELECT transactions.symbol, company.name, SUM(transactions.shares) FROM transactions INNER JOIN company ON transactions.symbol = company.symbol GROUP BY transactions.user_id, transactions.symbol HAVING SUM(transactions.shares) > 0 AND transactions.user_id = ?", user_id)
    # Check price of each shares and calculate grand total
    total = user[0]["cash"]
    for share in shares:
        share["price"] = lookup(share["symbol"])["price"]
        share["total"] = share["SUM(transactions.shares)"] * share["price"]
        total += share["total"]

    return render_template("index.html", shares=shares, balance=user[0]["cash"], total=total)


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
        user = db.execute("SELECT username, cash FROM users WHERE id = ?", user_id)
        if company["price"] * shares > user[0]["cash"]:
            return apology("Insufficient Fund")

        time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Update user's cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", user[0]["cash"] - company["price"] * shares, user_id)

        # Update company table for new company
        if not len(db.execute("SELECT symbol FROM company WHERE symbol = ?", symbol)):
            db.execute("INSERT INTO company (symbol, name) VALUES (?, ?)", symbol, company["name"])

        # Insert new transaction
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, time) VALUES (?, ?, ?, ?, ?)",
                   user_id, symbol, shares, company["price"], time)
        flash("Bought!")
        return redirect("/")

    # Method: "GET"
    return render_template("interface.html", task="buy")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT symbol, shares, price, time FROM transactions WHERE user_id = ?", session["user_id"])
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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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

        return render_template("interface.html", task="quoted", company=company)
    else:
        return render_template("interface.html", task="quote")


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

        users = db.execute("SELECT * FROM users WHERE username = (?)", username)

        if len(users) != 0:
            return apology("Username already taken")

        # Hash password so it can't be cracked by other people
        hash_password = generate_password_hash(password)
        user_id = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash_password)

        # Remember which user has logged in
        session["user_id"] = user_id

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
    stocks = db.execute(
        "SELECT symbol, SUM(shares) FROM transactions GROUP BY user_id, symbol HAVING SUM(shares) > 0 AND user_id = ?", session["user_id"])
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
        current_stock = [stock for stock in stocks if stock["symbol"] == symbol]
        if len(current_stock) != 1:
            return apology("Insufficient shares")
        if current_stock[0]["SUM(shares)"] < shares:
            return apology("Insufficient shares")

        user = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Update user's cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", user[0]["cash"] + company["price"] * shares, user_id)

        # Insert new transaction
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, time) VALUES (?, ?, ?, ?, ?)",
                   user_id, symbol, -shares, company["price"], time)
        flash("Sold!")
        return redirect("/")

    # Method: "GET"
    return render_template("interface.html", task="sell", symbols=stocks)


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """Change Password"""
    if request.method == "POST":
        curr_input = request.form.get("current")
        new_pass = request.form.get("new")
        confirm_pass = request.form.get("confirm")

        # Validate user input
        curr_pass = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])

        if not check_password_hash(curr_pass[0]["hash"], curr_input):
            return apology("Current password didn't match")
        if new_pass == "":
            return apology("Password must be 8 chracters or more")
        if new_pass != confirm_pass:
            return apology("New password didn't match")

        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(new_pass), session["user_id"])
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
