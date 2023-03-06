import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
import time

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# Special characters to check for in password
special_chars = " !#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
numbers = "1234567890"


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    stocks = db.execute(
        "SELECT symbol FROM transactions WHERE user_id = ? GROUP BY user_id, symbol", session["user_id"])

    for i in range(len(stocks)):
        price = lookup(stocks[i]["symbol"])["price"]
        name = lookup(stocks[i]["symbol"])["name"]
        db.execute("UPDATE transactions SET price = ?, name = ? WHERE symbol = ?", price, name, stocks[i]["symbol"])

    stocks = db.execute(
        "SELECT symbol, name, SUM(amount) as sum_amount, user_id, price, price*SUM(amount) as total_price FROM transactions WHERE user_id = ? GROUP BY user_id, symbol", session["user_id"])

    portfolio_value = 0

    for i in range(len(stocks)):
        portfolio_value += stocks[i]["total_price"]

    portfolio_value += db.execute(
        "SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

    return render_template("index.html", balance=db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"], stocks=stocks, portfolio_value=portfolio_value)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        searched = request.form.get("symbol")
        shares = request.form.get("shares")
        stock = lookup(searched)

        if not shares or not searched:
            return apology("Forms cannot be blank")

        try:
            shares = int(shares)
        except ValueError:
            return apology("Shares must be a positive whole number")

        if stock == None:
            return apology("The stock you searched for does not exist.")

        if shares <= 0:
            return apology("Shares must be a positive number")

        money = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        total_price = float(shares)*stock["price"]
        remaining_balance = round(float(money) - float(total_price), 2)

        date_time = time.strftime("%m/%d/%Y %H:%M:%S", time.localtime())

        if money <= total_price:
            return apology("Your funds are too low to complete this purchase")

        flash(f"Total price is {usd(total_price)}. Remaining Balance is {usd(remaining_balance)}")

        db.execute("UPDATE users SET cash = ? WHERE id = ?", remaining_balance, session["user_id"])
        db.execute("INSERT INTO transactions (symbol, amount, user_id, price, datetime) VALUES (?, ?, ?, ?, ?)",
                   stock["symbol"], shares, session["user_id"], total_price, date_time)

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT symbol, amount, price, price*ABS(amount) as sum_amount, datetime FROM transactions WHERE user_id = ?", session["user_id"])

    if len(transactions) == 0:
        return redirect("/")

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
        username = request.form.get("username").lower()
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
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
        searched = request.form.get("symbol")
        quote = lookup(searched)
        if quote == None:
            return apology("The stock you searched for does not exist.")

        return render_template("quoted.html", quote=quote)

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username").lower()
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username or not password or not confirmation:
            return apology("Username/Password is invalid or blank")

        if confirmation != password:
            return apology("Password and Confirmation do not match")

        contains_special = False
        contains_number = False

        for i in special_chars:
            if password.find(i) != -1:
                contains_special = True

        for i in numbers:
            if password.find(i) != -1:
                contains_number = True

        if not contains_special or not contains_number or len(password) < 8:
            return apology("Password must contain at least 8 characters, a number and a special character")

        # Tries to input the user into the database, unless the username has already been taken
        try:
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, generate_password_hash(password))
        except ValueError:
            return apology("Username has already been taken.")
        return redirect("/")
    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    stocks = db.execute(
        "SELECT symbol, SUM(amount) as amount FROM transactions WHERE user_id = ? GROUP BY symbol", session["user_id"])
    if request.method == "POST":
        selected = request.form.get("symbol")
        shares = request.form.get("shares")

        try:
            shares = int(shares)
        except ValueError:
            return apology("Shares invalid or blank")

        if not selected or not shares:
            return apology("Symbol/Shares invalid or blank")

        if not shares <= db.execute("SELECT SUM(amount) as amount FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY user_id, symbol", session["user_id"], selected)[0]["amount"]:
            return apology("You do not own that many shares of that stock")

        if shares <= 0:
            return apology("Shares must be a positive number")

        price = lookup(selected)["price"]*shares
        date_time = time.strftime("%m/%d/%Y, %H:%M:%S", time.localtime())
        db.execute("UPDATE users SET cash = cash+?", price)
        db.execute("INSERT INTO transactions (symbol, user_id, price, amount, datetime) VALUES (?, ?, ?, ?, ?)",
                   selected, session["user_id"], price, -shares, date_time)

        return redirect("/")

    return render_template("sell.html", stocks=stocks)
