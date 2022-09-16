import os
import sys

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

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
    user_id = session["user_id"] # Gets the user ID
    
    finances = db.execute("""SELECT symbol, name, SUM(shares) AS shares, price, SUM(price * shares) AS total, ROUND(cash, 2) AS cash
                            FROM buy
                            JOIN users ON buy.user_id = users.id 
                            WHERE user_id = ?
                            GROUP BY SYMBOL""", user_id)
    try:
        grand_total = sum([i['total'] for i in finances]) + finances[0]["cash"] # Sums all stocks together
        grands_total = [usd(grand_total)]
        money = [usd(finances[0]["cash"])]
        return render_template("index.html", finance = finances, grand = grands_total, monies = money)
    except: print("oh")
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    grand_total = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    money = [usd(cash[0]["cash"])]
    grands_total = [usd(cash[0]["cash"])]
    return render_template("index.html", grand = grands_total, monies = money)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = request.form.get("symbol")
        shares = request.form.get("shares", type=int)
        
        if not symbol:
            return apology("Must provide symbol")
            
        stock = lookup(symbol.upper())
        
        if stock == None:
            return apology("Stock does not exist")
            
        if not shares:
            return apology("Must provide number of shares")
            
        if shares < 1:
            return apology("invalid shares")
        
        transaction_value = shares * stock["price"]
        
        user_id = session["user_id"]
        user_cash_db = db.execute("SELECT cash FROM users WHERE id = :id", id=user_id)
        user_cash = user_cash_db[0]["cash"]
        
        if user_cash < transaction_value:
            return apology("ur broke my guy")
        
        new_cash = user_cash - transaction_value
        
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)
        
        now = datetime.now()
        date = now.strftime('%Y-%m-%d %H:%M:%S')
        
        db.execute("INSERT INTO buy (user_id, symbol, name, price, shares, transacted) VALUES(?, ?, ?, ?, ?, ?)", user_id, stock["symbol"], stock["name"], stock["price"], shares, date)
        
        flash("Bought!")
        
        return redirect("/")
        
        
@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"] # Get users session id
    # Load information needed
    transactions = db.execute("SELECT symbol, shares, price, transacted FROM buy WHERE user_id = ?", user_id)
    return render_template("history.html", history = transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password")

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
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")
        
        if not symbol.isalpha():
            return apology("Invalid input")
            
        if not symbol:
            return apology("Must give symbol")
        
        stock = lookup(symbol)
        
        if stock == None:
            return apology("Stock does not exist")
            
        return render_template("quoted.html", name = stock["name"], price = stock["price"], symbol = stock["symbol"])


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        # Gets users data from form
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        
        taken = db.execute("SELECT username FROM users WHERE username = ?", username)   # Stores username from database
        
        # Checks if username or password or confirmation is blank
        if not username:
            return apology("Username field is blank")
        if not password:
            return apology("password field is blank")
        if not confirmation:
            return apology("confirmation field is blank")
            
        # Checks if passwords match
        elif confirmation != password:
            return apology("Passwords do not match")
            
        # Checks if username is taken
        elif len(taken) != 0:
            return apology("Username is already taken")
        
        password_hash = generate_password_hash(password, "sha256")  # Hashes the user's password
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, password_hash)  # adds user's login to the database
        return redirect("/login")   # redirects user to login page
        
        
@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        user_id = session["user_id"] # Gets the user ID
        rows = db.execute("SELECT symbol FROM buy WHERE user_id = ? GROUP BY symbol", user_id) # Gets symbols of stocks the user owns
        SELL = [] # store the symbols in a list
        for row in rows: # loads the symbols in the list
            SELL.append({
                "symbol": row["symbol"]
            })
        return render_template("sell.html", sell=SELL)
    else:
        user_id = session["user_id"] # Gets the user ID

        symbol = request.form.get("symbol") # accesses forms symbol
        shares = int(request.form.get("shares")) # accesses forms amount to sell
        
        if not shares and not symbol:
            return apology("Please choose a stock and the amount to sell")
        if not symbol:
            return apology("Please choose a stock to sell")
        if not shares:
            return apology("Please choose the amount to sell")
        # to sell stock, remove that number of shares from buy
        # lookup the stock again for the price
        # add that amount to your new cash
        
        # Gets total shares
        share = db.execute("SELECT symbol, SUM(shares) AS totalShares FROM buy WHERE user_id = ? AND symbol = ? GROUP BY symbol", user_id, symbol)
        totalShares = share[0]["totalShares"]
        
        if totalShares < shares: # Check if you can sell that amount
            return apology("You don't have that many shares")
        
        stock = lookup(symbol)
        
        transaction_value = shares * stock["price"] # Value of how much you want to sell
        
        users_cash_db = db.execute("SELECT cash FROM users WHERE id = :id", id=user_id)
        users_cash = users_cash_db[0]["cash"]
        
        new_cash = users_cash + transaction_value
        
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)
        
        now = datetime.now()
        date = now.strftime('%Y-%m-%d %H:%M:%S')
        
        db.execute("INSERT INTO buy (user_id, symbol, name, price, shares, transacted) VALUES(?, ?, ?, ?, ?, ?)", user_id, stock["symbol"], stock["name"], stock["price"], shares*(-1), date)
        flash("Sold!")
        
        return redirect("/")
        
@app.route("/newpass", methods=["GET", "POST"])
@login_required
def newpass():
    """Let's user change password"""
    if request.method == "GET":
        return render_template("newpass.html")
    else:
        user_id = session["user_id"] # get users session id
        
        newpass = request.form.get("newpassword")
        confirm = request.form.get("confirmation")
        
        if not newpass and not confirm:
            return apology("Please enter a New Password")
        if not newpass:
            return apology("Please enter a New Password")
        if not confirm:
            return apology("Please enter the same password twice")
        
        newpass_hash = generate_password_hash(newpass)
        
        db.execute("UPDATE users SET hash = ? WHERE id = ?", newpass_hash, user_id)
            
        flash("Password Changed!")
        
    return redirect("/")