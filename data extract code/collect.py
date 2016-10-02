import numpy as np
import os
import re
import csv

path = '/home/hd/python/data_packet/test'
p = re.compile('\d*\s*.{15}\s*.{3}(\d{2}[.]\d{6})\s*(\w*)\s*(\d*)\s*\d*[.]\d*[.]\d*[.](\d*)\s*\d*[.]\d*[.]\d*[.]\d*\s*(\d*)\s*(\d*)\s*(\d*)')
file_count = 1;
line_count = 1;

csv_file = open('packet.csv', 'w')
cw = csv.writer(csv_file, delimiter=',',quotechar='|')

for root, dirs, files in os.walk(path):
	for filename in files:
		print str(file_count) + ' ' + filename
		file_count = file_count+1
		fd = open(path + '/' + filename, 'r')
		
		while True:
			line = fd.readline()
			if not line: break
			m = p.search(line)
			if m is not None:
				#print line_count
				line_count = line_count+1
				#print str(line_count) + ' %s %s %s %s %s %s %s' % (m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6), m.group(7))
				if m.group(2) == 'TCP':
					protocol = 1
				elif m.group(2) == 'UDP':
					protocol = 2
				elif m.group(2) == 'ICMP':
					protocol = 3
				cw.writerow([m.group(1),protocol,m.group(3),m.group(4),m.group(5),m.group(6),m.group(7)])
				
		fd.close()
csv_file.close()
