from flask import Flask,render_template,flash,redirect,url_for,session,request,logging
#from data import Articles  #to be removed
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import re
app = Flask(__name__)

#config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'hariroot'
app.config['MYSQL_DB'] = 'myworld'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
#init MYSQL
mysql = MySQL(app)
#Articles = Articles()
@app.route('/')
#Index
def index():

    return render_template('home.html')
#About
@app.route('/about')
def about():
    return render_template('about.html')
'''
#Articles
@app.route('/articles')
def articles():
    return render_template('articles.html', articles = Articles)
#Single Article
@app.route('/article/<string:id>/')
def article(id):
    return render_template('article.html',id=id)
'''
def pwdstrcheck(nm,emid,user,pwd):
    x = True
    while x:
        if (len(pwd)<8 or len(pwd)>12):
            break
        elif not re.search("[a-z]",pwd):
            break
        elif not re.search("[0-9]",pwd):
            break
        elif not re.search("[A-Z]",pwd):
            break
        elif not re.search("[$#@]",pwd):
            break
        elif re.search("\s",pwd):
            break
        else:
            #connection = pymysql.connect(host='localhost',user='root',passwd='Biju123',db='myworld')
            cur = mysql.connection.cursor()
            pwdhash = sha256_crypt.encrypt(pwd)
            #args = (nm,emid,user,pwd)
            #cur.execute("insert into pwdusers(name,username,emailid,password) values(%s,%s,%s,%s)",(nm,user,emid,pwd))
            cur.execute("INSERT INTO pwdusers(name,username,emailid,password) VALUES(AES_ENCRYPT(%s,'key1234'),%s,AES_ENCRYPT(%s,'key1234'),%s)",(nm,user,emid,pwdhash))
            mysql.connection.commit()
            cur.close()
            flash('You are now registered and can log in','success')
            x = False
            return False
            #flash('You are now registered and can log in','success')
            #return redirect(url_for('index'))
    if x:
        #print("Not a Strong Password")
        flash('Not a Strong Password','danger')
        #return render_template('register.html',form=form)
#Register Form Class
class RegisterForm(Form):
    name = StringField('Name',[validators.Length(min=1,max=50)])
    username = StringField('Username',[validators.Length(min=4,max=25)])
    email = StringField('Emailid',[validators.Length(min=6,max=50)])
    password = PasswordField('Password', [
    validators.DataRequired(),
    validators.EqualTo('confirm',message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

#User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        #password = sha256_crypt.encrypt(str(form.password.data))
        password = form.password.data
        #pwdstrcheck(name,email,username,password)
        if pwdstrcheck(name,email,username,password) == False:
            return redirect(url_for('index'))

        #Create Cursor
        #cur = mysql.connection.cursor()
        # Execute query
        #INSERT INTO pwdusers(name,username,emailid,password) VALUES(AES_ENCRYPT(%s,'key1234'),AES_ENCRYPT(%s,'key1234'),AES_ENCRYPT(%s,'key1234'),AES_ENCRYPT(%s,'key1234'));
        #cur.execute("INSERT INTO pwdusers(name,username,emailid,password) VALUES(%s,%s,%s,%s)",(name,username,email,password))
        #cur.execute("INSERT INTO pwdusers(name,username,emailid,password) VALUES(AES_ENCRYPT(%s,'key1234'),%s,AES_ENCRYPT(%s,'key1234'),AES_ENCRYPT(%s,'key1234'))",(name,username,email,password))
        #Commit to DB
        #mysql.connection.commit()

        #Close Connection
        #cur.close()

        #flash('You are now registered and can log in','success')
        #return redirect(url_for('index'))
        #return render_template('register.html')
    return render_template('register.html',form=form)
#User Login
@app.route('/login',methods=['GET','POST'])
def login():
    #return render_template('login.html',form=form)
    if request.method == 'POST':
    #return render_template('login.html',form=form)
        #Get form fields
        username = request.form['username']
        password_candidate = request.form['password']

        #Create cursor
        cur = mysql.connection.cursor()
        cur1 = mysql.connection.cursor()
        #Get user by username
        result = cur.execute('SELECT * from pwdusers where username=%s',[username])
        #select AES_DECRYPT(name,'key1234'),username,AES_DECRYPT(emailid,'key1234'),AES_DECRYPT(password,'key1234') from pwdusers where username = 'Barry';
        result1 = cur1.execute("select AES_DECRYPT(name,'key1234') as name,username,AES_DECRYPT(emailid,'key1234') as emailid from pwdusers where username = %s",[username])
        if result > 0:
            data = cur.fetchone()
            data1 = cur1.fetchone()
            password = data['password']
            #session['logged_in'] = True
            #session['username'] =  username

            #flash('You are now logged in', 'success')
            #flash(data1, 'success')
            #return render_template('dashboard.html',data2 = data1)

            #Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                app.logger.info('PASSWORD MATCHED')
                session['logged_in'] = True
                session['username'] =  username

                flash('You are now logged in', 'success')
                #return redirect(url_for('dashboard'))
                return render_template('dashboard.html',data2 = data1)
            else:
                #app.logger.info('PASSWORD NOT MATCHED')
                error = 'Invalid login'
                return render_template('login.html',error=error)

                #close connection
            cur.close()
            cur1.close()
        else:
            #app.logger.info('No user')
            error = 'Username not found'
            return render_template('login.html',error=error)
    return render_template('login.html')

#Check if user logged in

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login','danger')
            return redirect(url_for('login'))
    return wrap

#Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out','success')
    return redirect(url_for('login'))
#Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    return render_template('dashboard.html')


if __name__ == "__main__":
    app.secret_key='secret123'
    app.run(debug=True)
    #app.run()
