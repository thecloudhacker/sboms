from flask import Flask, render_template, session, request, redirect, url_for, make_response
from markupsafe import escape
import os
import configparser
import csv
import hashlib
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
import datetime
from datetime import datetime as dt


# Load APP Config from the file system settings
try:
    config = configparser.ConfigParser()
    config.read_file(open(r".appconfig"))
    AWS_ACCOUNT_ID=config.get('AWS', 'AWS_ACCOUNT_ID')
    AWS_REGION=config.get('AWS', 'AWS_REGION')
    AWS_KEY=config.get('AWS', 'AWS_KEY')
    AWS_SECRET=config.get('AWS', 'AWS_SECRET')
    SBOM_FOLDER=config.get('CLU', 'SBOM_FOLDER')
except:
    AWS_ACCOUNT_ID=""
    AWS_REGION=""
    AWS_KEY=""
    AWS_SECRET=""
    SBOM_FOLDER=""

# Initialise DB
db = SQLAlchemy()
# create the app
app = Flask(__name__)
db_name = 'sboms.db'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(BASE_DIR, db_name)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# initialize the app with Flask-SQLAlchemy db
db.init_app(app)

#################################################################
# SECRETS AND SALTS
# Set secret key for sessions
# This should be changed to a different item for each deployment
app.secret_key = 'Rand0mS3cr37wurdZ0987!'
APPSALT = '54ltyMc5aL7f4c3'
##################################################################




##################################################### MAIN AUTH AND HOMEPAGE
# Primary Route
@app.route('/')
def index():
    if 'username' in session:
        # Get Status of Warnings
        # Pull quantity of vulnerabilities currently tracked
        vulnCountSQL = db.session.query(vulnerabilities).count()
        vulnCount = str(vulnCountSQL)
        # Pull quantity of findings currently tracked
        foundCountSQL = db.session.query(findings).count()
        foundCount = str(foundCountSQL)
        if foundCountSQL == 0:
            mainInfo="All chill, zero thrill."
        else:
            mainInfo="ARGH! Malware in the Mainframe!"
        # Output the main page
        return render_template('index.html', mainInfo=mainInfo,vulnerabilityCount=vulnCount,findingCount=foundCount)
    else:
        return render_template('auth.html',imgBox="img/doomguy.gif")


# AUTH ROUTE POINTS 
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        okayAuth = checkAuth(request.form['username'],request.form['password'])
        if okayAuth == True:
            session['username'] = request.form['username']
            return redirect(url_for('index'))
        else:
            session.pop('username', None)
            return render_template('auth.html',failmessage="I don't recognise you.",imgBox="img/doomguy.gif")
    else:
        return render_template('auth.html',imgBox="img/doomguy.gif")



# Run authentication with database
def checkAuth(myusername,password):
    # Hash the string to SHA1
    mypassword = str(APPSALT + password)
    hashstring = hashlib.sha1(mypassword.encode()).hexdigest()
    try:
        query = db.session.query(users).filter(users.username==myusername, users.userpass==hashstring)
        result = query.first()
        if result:
            return True
        else:
            return False
    except:
        return False


@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    session.pop('password', None)
    return redirect(url_for('index'))


# Home Screen
def home():
    return render_template('index.html')



######### MAIN PAGE FUNCTIONS ##############


# Display Reports
@app.route('/reports')
def show_reports():
    # Display the current reports
    if 'username' in session:
        return render_template('reports.html')
    else:
        return render_template('auth.html')


@app.route('/reports/vulnerabilities')
def show_reports_vulnerabilities():
    # Display all the vulnerabilities tracked
    if 'username' in session:
        
        tableData=""
        vulnerabilityList = db.session.execute(db.select(vulnerabilities)
                    .order_by(vulnerabilities.packagename)).scalars()
        for item in vulnerabilityList:
            tableData += "<tr><td>" + item.packagename + "</td><td>" + item.packageversion + "</td><td>" + item.dateAdded + "</td></tr>"
        return render_template('reports_vulnerabilities.html',mainTable=tableData)
    else:
        return render_template('auth.html')

@app.route('/reports/findings')
def show_reports_findings():
    # Display all the items we have found
    if 'username' in session:
        tableData=""
        findingList = db.session.execute(db.select(findings)
                    .order_by(findings.findingDate)).scalars()
        for item in findingList:
            # Grab the vulnerability item from the table
            vulnerabilityList = db.session.execute(db.select(vulnerabilities)
                        .filter_by(vulnerabilityid=item.vulnerabilityid))
            for packageitem in vulnerabilityList:
                    packageVuln = packageitem['packagename']
            tableData += "<tr><td>" + item.findingDate + "</td><td>" + packageVuln + "</td></tr>"
        return render_template('reports_vulnerabilities.html',mainTable=tableData)
    else:
        return render_template('auth.html')



##################################################### SETTINGS

# Display Settings
@app.route('/settings', methods=['GET', 'POST'])
def show_settings():
    if 'username' in session:
        updatemsg = ""
        if request.method == 'POST':
            completeFileContents = "[AWS]\nAWS_ACCOUNT_ID = " + request.form['accountID'] + "\nAWS_REGION = " + request.form['region'] + "\nAWS_KEY = " + request.form['userkey'] + "\nAWS_SECRET = " + request.form['usersecret'] + "\n[CLU]\nSBOM_FOLDER = " + request.form['sbomfolder'] + "\n"
            # Save settings
            try:
                f = open(".appconfig", "w")
                f.write(completeFileContents)
                f.close()
                updatemsg = "Settings Stored"
            except: 
                updatemsg = "Error Saving Settings"
        # Display the current settings
        # Load the user list
        userList = ""
        
        return render_template('settings.html',accountID=AWS_ACCOUNT_ID, region=AWS_REGION, userkey=AWS_KEY, usersecret=AWS_SECRET, sbomfolder=SBOM_FOLDER, userList=userList,updatemsg=updatemsg)
    else:
        return render_template('auth.html')


################## Database Specification #################################### Database Specification ##################

class vulnerabilities(db.Model):
    __tablename__ = 'vulnerabilities'
    vulnerabilityid = db.Column(db.Integer, primary_key=True)
    packagename = db.Column(db.String)
    packageversion = db.Column(db.String)
    dateAdded = db.Column(db.String)

    def __init__(self,packagename,packageversion,vulnerabilityid):
        self.packagename = packagename
        self.packageversion = packageversion
        self.vulnerabilityid = vulnerabilityid

class findings(db.Model):
    __tablename__ = 'findings'
    findingid = db.Column(db.Integer, primary_key=True)
    findingDate = db.Column(db.String)
    vulnerabilityid = db.Column(db.Integer)

class users(db.Model):
    __tablename__ = 'users'
    userid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    userpass = db.Column(db.String)
    lastlogin = db.Column(db.String)
    
    def __init__(self,username,userpass,lastlogin):
        self.username = username
        self.userpass = userpass
        self.lastlogin = lastlogin



#########################################################################################################################




##################################################### APP SETUP

# Failure to load that page - throw a 404
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html'), 404

# Run the main system on port 5000
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    app.run(debug=True, host='0.0.0.0', port=port)