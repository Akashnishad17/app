from flask import Flask, request, render_template,url_for, redirect, session, flash, abort ,g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager,login_user , logout_user , current_user , login_required
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow
from flask_mobility import Mobility
from flask_mobility.decorators import mobile_template
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import datetime
import os

app = Flask(__name__)
app.jinja_env.add_extension('jinja2.ext.loopcontrols')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///E:/app/flaskmobility/arjun/TBD.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'testingthinkbigdata@gmail.com'
app.config['MAIL_PASSWORD'] = ''
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'testingthinkbigdata@gmail.com'

app.config['SECRET_KEY'] = b''

mail = Mail(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
ma = Marshmallow(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message = "You need to login first."
login_manager.init_app(app)
Mobility(app)

s = URLSafeTimedSerializer('') 

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(80))
    lastname = db.Column(db.String(80))
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(80))
    email = db.Column(db.String(120), unique=True)
    role = db.Column(db.String(10))
    
    def __init__(self, firstname, lastname, username, password, email, role):
        self.firstname = firstname
        self.lastname = lastname
        self.username = username
        self.password = password
        self.email = email
        self.role = role

    def is_authenticated(self):
        return True
 
    def is_active(self):
        return True
 
    def is_anonymous(self):
        return False
 
    def get_id(self):
        return (self.id)
 
    def __repr__(self):
        return '<User %r>' % (self.username)

class UserSchema(ma.Schema):
    fields = ('id','firstname','lastname','username','password','email','role')

user_schema = UserSchema(strict=True) 
users_schema = UserSchema(many=True, strict=True)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    eventname = db.Column(db.String(80))
    venue = db.Column(db.String(80))
    date = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(20), nullable=False)
    eventhead = db.Column(db.String(80))
    certified = db.Column(db.String(10))
    poster = db.Column(db.LargeBinary,nullable=True)
    
    def __init__(self, eventname, venue, date,time, eventhead, certified, poster):
        self.eventname = eventname
        self.venue = venue
        self.date = date
        self.time = time
        self.eventhead = eventhead
        self.certified = certified
        self.poster = poster

class EventSchema(ma.Schema):
    fields = ('id','eventname','venue','date','time','eventhead','certified','poster')

event_schema = EventSchema(strict=True) 
events_schema = EventSchema(many=True, strict=True)

class UserParticipation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, nullable=False)
    eventid = db.Column(db.Integer, nullable=False)
    registereddatetime = db.Column(db.DateTime())

    def __init__(self, userid, eventid, registereddatetime):
        self.userid = userid
        self.eventid = eventid
        self.registereddatetime = registereddatetime

class UserParticipationSchema(ma.Schema):
    fields = ('id','userid','eventid','registereddatetime')

userparticipation_schema = UserParticipationSchema(strict=True)
userparticipations_schema = UserParticipationSchema(many=True, strict=True)

class UserQuery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    email = db.Column(db.String(80))
    query = db.Column(db.String(300))
    querytime = db.Column(db.DateTime())
    

def __init__(self, name, email, query, querytime):
        self.name = name
        self.email = email
        self.query = query
        self.querytime = querytime

class UserQuerySchema(ma.Schema):
    fields = ('id','name','email','query','querytime')

userquery_schema = UserQuerySchema(strict=True) 
userquerys_schema = UserQuerySchema(many=True, strict=True)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/About')
def about():
    return render_template("about.html")

@app.route('/ContactUs', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':        
        userquery = UserQuery(name=request.form['name'],email=request.form['email'],query=request.form['query'],querytime=datetime.datetime.now())
        db.session.add(userquery)
        db.session.commit()
        flash('Your query has been sent')
        return render_template("login.html")
    return render_template("contact.html")

#admin routings
@app.route('/admin/')
@login_required
def admin():
    if not current_user.role=='admin':
        logout_user()
        return render_template("login.html")
    event_count=Event.query.count()
    user_count=User.query.count()
    userparticipation_count=UserParticipation.query.count()
    return render_template("adminhome.html",event_count=event_count,user_count=user_count,userparticipation_count=userparticipation_count)

@app.route('/admin/CreateNewEvent', methods=['GET', 'POST'])
@login_required
def admincreatenewevent():
    if not current_user.role=='admin':
        logout_user()
        return render_template("login.html")
    if request.method == 'POST':
        file = request.files['poster']
        event = Event(eventname=request.form['eventname'],venue=request.form['venue'],date=request.form['date'],time=request.form['time'],eventhead=request.form['eventhead'],certified=request.form['certification'],poster=file.read())
        db.session.add(event)
        db.session.commit()
        flash('You created an event')
        return redirect(url_for("admineventlist"))
    return render_template("admincreatenewevent.html")

event = None
@app.route('/admin/EventList',methods=['GET', 'POST'])
@login_required
def admineventlist():
    if not current_user.role=='admin':
        logout_user()
        return render_template("login.html")
    admin_eventlist=Event.query.all()
    eventpart_list = UserParticipation.query.all()
    eventpart_list = [ part.eventid for part in eventpart_list]
    if request.method == "POST":
        if request.form['option'] == 'delete':
            even = Event.query.filter_by(id = request.form['eventid']).first()
            participation = UserParticipation.query.filter_by(eventid = request.form['eventid']).all()
            db.session.delete(even)
            for part in participation:
                db.session.delete(part)
            db.session.commit()
            flash('The event has been deleted')
            return redirect(url_for('admineventlist'))
        if request.form['option'] == 'update':
            global event
            event = Event.query.filter_by(id = request.form['eventid']).first()
            return redirect(url_for('adminupdateevent'))
        if request.form['option'] == 'show':
            userparticipation = UserParticipation.query.filter_by(eventid = request.form['eventid']).all()
            userparticipation = [part.userid for part in userparticipation]
            user_list = User.query.filter_by(role='user').all()
            return render_template("adminshowuserevent.html",user_list=user_list,userparticipation=userparticipation)
    return render_template("admineventlist.html",admin_eventlist=admin_eventlist,eventpart_list=eventpart_list)

@app.route('/admin/UpdateEvent',methods=['GET', 'POST'])
@login_required
def adminupdateevent():
    if not current_user.role=='admin':
        logout_user()
        return render_template("login.html")
    global event
    if request.method == "POST":
        global event
        even = db.session.query(Event).filter_by(id = event.id).update(dict(eventname=request.form['eventname'],venue=request.form['venue'],date=request.form['date'],time=request.form['time'],eventhead=request.form['eventhead'],certified=request.form['certification']))
        db.session.commit()
        event = None
        flash('The event has been updated')
        return redirect(url_for('admineventlist'))
    return render_template('adminupdateevent.html',event=event)

@app.route('/admin/UserList',methods=['GET', 'POST'])
@login_required
def adminuserlist():
    if not current_user.role=='admin':
        logout_user()
        return render_template("login.html")
    adminlist=User.query.filter_by(role='admin').all()
    userlist=User.query.filter_by(role='user').all()
    if request.method == 'POST':
        user = User.query.filter_by(id=request.form['userid']).first()
        userpart = UserParticipation.query.filter_by(userid=request.form['userid']).all()
        db.session.delete(user)
        for part in userpart:
            db.session.delete(part)
        db.session.commit()
        flash('User has been deleted')
        return redirect(url_for('adminuserlist'))
    return render_template("adminuserlist.html",adminlist=adminlist,userlist=userlist)

@app.route('/admin/About')
@login_required
def adminabout():
    if not current_user.role=='admin':
        logout_user()
        return render_template("login.html")
    return render_template("about.html")

@app.route('/admin/UserQuery',methods=['GET', 'POST'])
@login_required
def adminuserquery():
    if not current_user.role=='admin':
        logout_user()
        return render_template("login.html")
    admin_userquery=db.session.query(UserQuery.id,UserQuery.name,UserQuery.email,UserQuery.query).all()
    if request.method == 'POST':
        userquery = db.session.query(UserQuery).filter_by(id=request.form['userqueryid']).first()
        db.session.delete(userquery)
        db.session.commit()
        return redirect(url_for('adminuserquery'))
    return render_template("adminuserquery.html",admin_userquery=admin_userquery)
        

@app.route('/admin/EditProfile', methods=['GET', 'POST'])
@login_required
def adminedit():
    if not current_user.role=='admin':
        logout_user()
        return render_template("login.html")
    admin=User.query.filter_by(id=current_user.get_id()).first()
    if request.method=='POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.id != current_user.get_id():
            flash('The username is already taken')
            return redirect(url_for("adminedit"))
        else:
            user = User.query.filter_by(email=request.form['email']).first()
            if user and user.id != current_user.get_id():
                flash('Aready have an account with this email')
                return redirect(url_for("adminedit"))
            else:
                user = User.query.filter_by(id=current_user.get_id()).update(dict(firstname=request.form['firstname'],lastname=request.form['lastname'],username=request.form['username'],email=request.form['email']))
                db.session.commit()
                flash('You have updated your profile')
                return redirect(url_for("admin"))   
    return render_template("adminedit.html",admin=admin)

@app.route('/admin/ChangePassword', methods=['GET', 'POST'])
@login_required
def adminchangepassword():
    if not current_user.role=='admin':
        logout_user()
        return render_template("login.html")
    if request.method == 'POST':
        admin = User.query.filter_by(id = current_user.get_id()).first()
        if bcrypt.check_password_hash(admin.password, request.form['old-password']):
            if request.form['new-password'] == request.form['rep-password']:
                newpassword = bcrypt.generate_password_hash(request.form['new-password'], 10)
                user = User.query.filter_by(id=current_user.get_id()).update(dict(password=newpassword))
                db.session.commit()
                flash('Your password has been updated')
                return redirect(url_for('admin'))
            else:
                flash('Password does not match')
                return redirect(url_for('adminchangepassword'))
        else:
            flash('You entered the wrong password')
            return redirect(url_for('adminchangepassword'))
    return render_template("adminchangepassword.html")

@app.route('/admin/Option')
@login_required
def adminoption():
    if not current_user.role=='admin':
        logout_user()
        return render_template("login.html")
    return render_template("adminoption.html")
#end of admin routings

#user routings
@app.route('/user/')
@login_required
def user():
    if not current_user.role=='user':
        logout_user()
        return render_template("login.html")
    event_count=Event.query.count()
    participation_count=UserParticipation.query.filter_by(userid=current_user.get_id()).count()
    return render_template("userhome.html",event_count=event_count,participation_count=participation_count)

@app.route('/user/About')
@login_required
def userabout():
    if not current_user.role=='user':
        logout_user()
        return render_template("login.html")
    return render_template("about.html")

@app.route('/user/ContactUs', methods=['GET', 'POST'])
@login_required
def usercontact():
    if not current_user.role=='user':
        logout_user()
        return render_template("login.html")
    user = User.query.filter_by(id=current_user.get_id()).first() 
    if request.method == 'POST':
        userquery = UserQuery(name=request.form['name'],email=request.form['email'],query=request.form['query'],querytime=datetime.datetime.now())
        db.session.add(userquery)
        db.session.commit()
        flash('Your query has been sent')
        return redirect(url_for("user"))
    return render_template("usercontact.html",user=user)

@app.route('/user/EventList', methods=['GET', 'POST'])
@login_required
def usereventlist():
    if not current_user.role=='user':
        logout_user()
        return render_template("login.html")
    userparticipation_list=UserParticipation.query.filter_by(userid=current_user.get_id()).all()
    userparticipation_list=[part.eventid for part in userparticipation_list]
    user_eventlist=Event.query.all()
    if request.method == 'POST':
        participation = UserParticipation(userid = current_user.get_id(),eventid = request.form['eventid'], registereddatetime = datetime.datetime.now())
        db.session.add(participation)
        db.session.commit()
        return redirect(url_for('usereventlist'))   
    return render_template("usereventlist.html",user_eventlist=user_eventlist,userparticipation_list=userparticipation_list)

@app.route('/user/MyRegistration', methods=['GET', 'POST'])
@login_required
def usermyregistration():
    if not current_user.role=='user':
        logout_user()
        return render_template("login.html")
    userparticipation_list=UserParticipation.query.filter_by(userid=current_user.get_id()).all()
    userparticipation_list=[part.eventid for part in userparticipation_list]
    user_eventlist=Event.query.all()
    if request.method == 'POST':
        participation = UserParticipation.query.filter_by(userid = current_user.get_id(),eventid = request.form['eventid']).first()
        db.session.delete(participation)
        db.session.commit()
        return redirect(url_for('usermyregistration'))
    return render_template("usermyregistration.html",userparticipation_list=userparticipation_list,user_eventlist=user_eventlist)

@app.route('/user/EditProfile', methods=['GET', 'POST'])
@login_required
def useredit():
    if not current_user.role=='user':
        logout_user()
        return render_template("login.html")
    user_per=User.query.filter_by(id=current_user.get_id()).first()
    if request.method=='POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.id != current_user.get_id():
            flash('The username is already taken')
            return redirect(url_for("useredit"))
        else:
            user = User.query.filter_by(email=request.form['email']).first()
            if user and user.id != current_user.get_id():
                flash('Aready have an account with this email')
                return redirect(url_for("useredit"))
            else:
                user = User.query.filter_by(id=current_user.get_id()).update(dict(firstname=request.form['firstname'],lastname=request.form['lastname'],username=request.form['username'],email=request.form['email']))
                db.session.commit()
                flash('You have updated your profile')
                return redirect(url_for("user"))   
    return render_template("useredit.html",user=user_per)

@app.route('/user/ChangePassword', methods=['GET', 'POST'])
@login_required
def userchangepassword():
    if not current_user.role=='user':
        logout_user()
        return render_template("login.html")
    if request.method == 'POST':
        user = User.query.filter_by(id = current_user.get_id()).first()
        if bcrypt.check_password_hash(user.password, request.form['old-password']):
            if request.form['new-password'] == request.form['rep-password']:
                newpassword = bcrypt.generate_password_hash(request.form['new-password'], 10)
                user = User.query.filter_by(id=current_user.get_id()).update(dict(password=newpassword))
                db.session.commit()
                flash('Your password has been updated')
                return redirect(url_for('user'))
            else:
                flash('Password does not match')
                return redirect(url_for('userchangepassword'))
        else:
            flash('You entered the wrong password')
            return redirect(url_for('userchangepassword'))
    return render_template("userchangepassword.html")

@app.route('/user/Option')
@login_required
def useroption():
    if not current_user.role=='user':
        logout_user()
        return render_template("login.html")
    return render_template("useroption.html")
#end of user routings

@app.route('/LogIn', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated and current_user.role == 'admin':
        return redirect(url_for('admin'))
    elif current_user.is_authenticated and current_user.role == 'user':
        return redirect(url_for('user'))
    if request.method == 'GET':
        return render_template('login.html')
    username = request.form['username']
    password = request.form['password']
    role_admin = 'admin'
    role_user = 'user'
    admin = User.query.filter_by(username=username,role=role_admin).first()
    user = User.query.filter_by(username=username,role=role_user).first()
    
    if admin is None:
        if user is None:
            flash('Username or Password is invalid')
            return render_template("login.html")
        elif bcrypt.check_password_hash(user.password, password):
            login_user(user,remember=True)
            return render_template('log.html',role='user')
        else:
            flash('Username or Password is invalid')
            return render_template("login.html")
    elif bcrypt.check_password_hash(admin.password, password):
        login_user(admin,remember=True)
        return render_template('log.html',role='admin')
    else:
        flash('Username or Password is invalid')
        return render_template("login.html")
    return render_template("login.html")

@app.before_request
def before_request():
    g.user =current_user

@app.route('/SignUp', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user:
            flash('The username is already taken')
            return render_template("signup.html")
        else:
            user = User.query.filter_by(email=request.form['email']).first()
            if user:
                flash('Aready have an account with this email')
                return render_template("signup.html")
            else:
                if request.form['password'] != request.form['rep-password']:
                    flash('Password does not match')
                    return render_template("signup.html")
                else:
                    user = User(firstname=request.form['firstname'],lastname=request.form['lastname'],username=request.form['username'], password=bcrypt.generate_password_hash(request.form['password'], 10),email=request.form['email'],role='user')
                    db.session.add(user)
                    db.session.commit()
                    flash('You have created an account')
                    return render_template("login.html")
    return render_template("signup.html")

email = None
@app.route('/ForgetPassword',methods=['GET','POST'])
def forgetpassword():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user is None:
            flash('There is no account with this email ID')
            return redirect(url_for('forgetpassword'))
        else:
            global email
            email = request.form['email']
            reset = s.dumps(email,salt='reset-password')
            msg = Message('Reset Your Password', sender = 'testingthinkbigdata@gmail.com', recipients = [email])
            link = url_for('resetpassword', reset=reset, _external = True)
            msg.body = "You can reset your password by clicking on the given link {}".format(link)
            mail.send(msg)
            flash('A reset password link has been sent to this email')
            return redirect(url_for('forgetpassword'))
    return render_template("forgetpassword.html")

@app.route('/resetpassword/<reset>',methods=['GET','POST'])
def resetpassword(reset):
    try:
        temp = s.loads(reset, salt='reset-password',max_age=120) #link valid for 2 minute
        if request.method == 'POST':
            if request.form['new-password'] == request.form['rep-password']:
                newpassword = bcrypt.generate_password_hash(request.form['new-password'], 10)
                global email
                user = User.query.filter_by(email=email).update(dict(password=newpassword))
                db.session.commit()
                email = None
                flash('Your password has been updated')
                return render_template("login.html")
            else:
                flash('Password does not match')
                return render_template("resetpassword.html",reset=reset)
    except SignatureExpired:
        flash('The link has been expired. Retry Again')
        return redirect(url_for('forgetpassword'))
    return render_template("resetpassword.html",reset=reset)

@app.route('/logout')
def logout():
    logout_user()
    return render_template("logout.html")     

if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True)
