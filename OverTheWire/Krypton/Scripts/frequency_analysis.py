#!/usr/bin/python3

# Script by Mike Rosinsky

import sys

if __name__=="__main__":

	char_table = {}
	char_total = 0
	groupsize = 0
	current_list = []
	frequency_list = "ETAOINSRHDLUCMFYWGPBVKXQJZ"

	#Check Argument Counts
	if len(sys.argv) != 3:
		print("Usage: python3 freq_analysis.py filename groupsize")
		exit(0)
	else:

		try:
			groupsize = int(sys.argv[2])
		except:
			print("groupsize must be an int")
			exit(0)

		# Try to Open the specified file
		try:
			with open(sys.argv[1]) as fh:
				lines = fh.readlines()
		except:
			print("No file named '" + sys.argv[1] + "'")
			exit(0)

		for line in lines:
			line = line.replace(" ", "")
			line = line.replace("\n", "")
			for i in range(len(line) - groupsize):
				group = line[i:i+groupsize]
				if group in char_table:
					char_table[group] += 1
				else:
					char_table[group] = 1

		char_table = sorted(char_table.items(), key=lambda x: x[1], reverse=True)

		for char in char_table:
			print(char[0] + ":\t" + str(char[1]))
			current_list.append(char[0])
	print("Current Frequency :","".join(current_list))
	print("Frequency    List :",frequency_list)
