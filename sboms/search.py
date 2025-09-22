import csv
import sqlite3
import os
import datetime
from datetime import datetime as dt
import re
import configparser

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


connection = sqlite3.connect('sboms.db')
cursor = connection.cursor()

# Get the Date Time
today = datetime.datetime.today()
dayOfWeek = today.weekday()
# Get the current time
findingdate = dt.now().strftime('%Y-%m-%d %H:%M')


# Create grep function
def grep(regex, path, file):
    filepath = os.path.join(path, file)
    try:
        with open(filepath) as f:
            results = re.findall(regex, f.read())
            if len(results) != 0:
                return f"{filepath} --> {results}"
    except UnicodeDecodeError:
        pass

intcounter = 1
# Grab vulnerability list from the DB
vulnerabilityList = "SELECT * FROM vulnerabilities"
cursor.execute(vulnerabilityList)
records = cursor.fetchall()
vulnquantity = len(records)
print("SEARCHING THROUGH " + str(vulnquantity) + " RECORDS")

for row in records:
    # For each vulnerability run a scan
    findingList = ""
    vulnerabilityid = row[3]
    package = row[0]
    version = row[1]
    packageToFind = package + "@" + version

    regex = re.compile(r'^.' + re.escape(packageToFind))
    folder = SBOM_FOLDER 
    print("(" + str(intcounter) + "/" + str(vulnquantity) + ") LOOKING FOR: " + packageToFind)
    for path, _, files in os.walk(folder):
        for file in files:
            filepath = os.path.join(path, file)
            try:
                with open(filepath) as f:
                    for line_number, line in enumerate(f):
                        results = re.findall(regex, line)
                        if len(results) != 0:
                            print(f"{filepath} --> {results}")
                            # Found a result
                            findingDetail = filepath + "  :::  " + results
                            # On finding an issue throw info into the DB
                            print("FOUND IN " + filepath)
                            insert_records = "INSERT INTO findings (findingDate, vulnerabilityid, findingDetail) VALUES(" + findingdate + " , " + vulnerabilityid + "," + findingDetail + ")"
                            cursor.execute(insert_records)
                            # Committing the changes
                            connection.commit()

            # We get an UnicodeDecodeError when reading binary files
            except UnicodeDecodeError:
                pass    
    intcounter += 1
# closing the database connection
connection.close()