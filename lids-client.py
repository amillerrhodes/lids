#!/usr/bin/python
# -*- coding: utf-8 -*-

import sqlite3 as lite
import pprint
import sys
from collections import defaultdict

con = lite.connect('lids.db')

counts = defaultdict(int)

with con:
    
    cur = con.cursor()    
    cur.execute('SELECT * FROM THREATS')
    
    data = cur.fetchall()
    for entry in data:
        counts[entry[0]] += 1
    
    counts = counts.items()
    counts.sort(key=lambda x: x[1])
    print "IP\t\tRule Match Count"
    for i, j in reversed(counts):
        print "%s\t%d" % (i, j)

