import string
import sys
import src.settings

def readdata(file):
    f=open(file)
    lines=f.readlines()
    data = []
    if len(lines)>0:
        for i in range(len(lines)):
            data.append(lines[i].split(' '))
            data[i] = data[i][:-1]
    return data, lines

def getdata(f):
    file_data = []
    file_info,lines = readdata(f)
    for i in range(len(lines)):
    	file_data.append(list(map(int, file_info[i])))
    return file_data,lines

class run_getdata:

	def __init__(self, name):
		self.pkts = []

	def principal(self, p4_code):

		file_info,lines = getdata(p4_code)

		for i in range(len(lines)):
			src.settings.burst_len.append(file_info[i][0])
			src.settings.burst_list_val.append(file_info[i][1:])