from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_super_secret_key' # Change this!

# In-memory 'database' for demonstration (use real DB in production!)
users_db = {}

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Add minimum password length check
        if len(password) < 4:
            error = 'Password must be at least 4 characters long!'
            return render_template('signup.html', error=error)

        if username in users_db:
            error = 'User already exists!'
            return render_template('signup.html', error=error)

        users_db[username] = generate_password_hash(password)
        return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_hash = users_db.get(username)
        if user_hash and check_password_hash(user_hash, password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials!'
            return render_template('login.html', error=error)
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', name=session['username'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
