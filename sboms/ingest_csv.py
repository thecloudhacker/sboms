import csv
import sqlite3
import os
import datetime
from datetime import datetime as dt

connection = sqlite3.connect('clu.db')
cursor = connection.cursor()

# Get the Date Time
today = datetime.datetime.today()
dayOfWeek = today.weekday()
# Get the current time
ingestiongdate = dt.now().strftime('%Y-%m-%d %H:%M')

file = open('vulnlist.csv')
contents = csv.reader(file)
insert_records = "INSERT INTO vulnerabilities (packagename,packageversion,dateAdded) VALUES(?, ?, '" + ingestiongdate + "')"
cursor.executemany(insert_records, contents)
# Committing the changes
connection.commit()
# closing the database connection
connection.close()