#!/usr/bin/python2.7
#
# Small script to show PostgreSQL and Pyscopg together
#

import psycopg2

try:
    conn = psycopg2.connect("dbname='segw' user='postgres' host='localhost' password='vijay'")
except:
    print "I am unable to connect to the database"

try:
    cur = conn.cursor()
    cur.execute("""SELECT * from endpoint where ip = 1""")
    rows = cur.fetchall()
    print "connected"
    print rows
except Exception as e:
    print "exception", str(e)
