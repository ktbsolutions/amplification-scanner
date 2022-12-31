# https://github.com/ktbsolutions/amplification-scanner
# Made for py3. Tested on Windows & Linux (Ubuntu 22.04.1 LTS)
# Use only for systems you own or have EXPLICIT permission to test.
# Unauthorized portscanning is at best rude and at worst illegal.

### imports
import socket
import time
import random
import json
import argparse
from datetime import datetime

### vars
hosts = []
detect_tasks = []
measure_tasks = []
results = []
vectors = [
	{
		"name": "DNS_A",
		"port": 53,
		"payload": "\x61\xe4\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x0c\x00\x0a\x00\x08\x98\x66\x4e\xc7\x05\x24\xbb\x9e"
	},
	{
		"name": "DNS_ANY",
		"port": 53,
		"payload": "\xf1\xe8\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x02\x73\x6c\x00\x00\xff\x00\x01\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x0c\x00\x0a\x00\x08\xc0\x4e\xd3\x88\xf7\x91\x6b\xb6"
	},
	{
		"name": "NTP",
		"port": 123,
		"payload": "\x17\x00\x03\x2a\x00\x00\x00\x00"
	},
	{
		"name": "cLDAP",
		"port": 389,
		"payload": "\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00"
	},
]
vector_human = "Name		Port	Payload Size\n____________________________________\n"
for vector in vectors:
	vector_human = vector_human + str((vector["name"])) + "		" + str(vector["port"]) + "	" + str(len(vector["payload"])) + " Bytes \n"

### funcs
def average(lst):
    return sum(lst) / len(lst)
def backspace(x):
        for i in range(x):
                print('\b \b', flush=True, end='')
def add_host(host):
	global hosts
	# This is lazy I know
	if host[-3:] == '/24':
		host = host[:-3] # Remove the /24
		host = host.rsplit(".")[:-1] # Split the host into octets
		for dClass in range(256):
			hosts.append(str(host[0]) + "." + str(host[1]) + "." + str(host[2]) + "." + str(dClass))
	else:
		hosts.append(host)
def add_detect_task(host, vectorname):
	for vector in vectors:
		if vector["name"] == vectorname:
			payload = vector["payload"]
			port = vector["port"]
	if len(payload) > 0:
		detect_tasks.append({"host": host, "name": vectorname, "port": port, "payload": payload})
def add_measure_task(host, vectorname):
	for vector in vectors:
		if vector["name"] == vectorname:
			payload = vector["payload"]
			port = vector["port"]
	if len(payload) > 0:
		measure_tasks.append({"host": host, "name": vectorname, "port": port, "payload": payload})
def add_result(result):
	results.append(result)
def scan_host(task, timeout):
	client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	client_socket.settimeout(timeout)
	payload = b"{task['payload']}"
	addr = (str(task["host"]), int(task["port"]))
	start = time.time()
	client_socket.sendto(payload, addr)
	try:
		data, server = client_socket.recvfrom(1024)
		end = time.time()
		elapsed = end - start
		elapsed = int((elapsed * 1000))
		add_measure_task(task["host"], task["name"])
	except socket.error:
		return 0
def measure_host(task, timeout):
	amount = 50
	failed = 0
	response_sizes = []
	response_latency = []
	for pings in range(amount):
		client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		client_socket.settimeout(timeout)
		payload = b"{task['payload']}"
		addr = (str(task["host"]), int(task["port"]))
		start = time.time()
		client_socket.sendto(payload, addr)
		try:
			data, server = client_socket.recvfrom(1024)
			end = time.time()
			elapsed = end - start
			elapsed = int((elapsed * 1000))
			response_sizes.append(len(data))
			response_latency.append(elapsed)
		except socket.error:
			failed += 1
	hitrate = str(failed)+"/"+str(amount)
	amp_factor = average(response_sizes)/len(task["payload"])
	amp_factor = str(amp_factor)[0:4]
	latency = average(response_latency)
	latency = str(latency)[0:4]
	add_result({"host": task["host"], "port": task["port"], "name": task["name"], "hitrate": hitrate, "amp_factor": amp_factor, "latency": latency})
# validation
parser = argparse.ArgumentParser(description='A simple tool for finding open UDP applications vulnerable to amplification and reflection')
parser._optionals.title = "arguments"

parser.add_argument('--hosts', help='Valid IPv4 (can be comma separated for multiple addresses or /24 multiple ranges) e.g. 192.168.0.1 192.168.0.0/24 ')
parser.add_argument('--vectors', help='OPTIONAL. Define vectors you want to search for, if left empty then all vectors will be included in the scan. [--vectors display] to list all vectors', default='all')
parser.add_argument('--timeout', help='OPTIONAL. Define timeout for each UDP packet in ms, 250ms default', default='250')

args = vars(parser.parse_args())

if args['vectors'] == 'display':
	print(vector_human)
	exit()
if args['hosts'] == None:
	print('No hosts to scan!')
	exit()
timeout = int(args['timeout'])
timeout = timeout / 1000.0
# tasking
print("Starting amplification-scanner ( https://github.com/ktbsolutions/amplification-scanner ) at " + str(datetime.now()))
for host in args['hosts'].split(","):
	add_host(host)

if args['vectors'] == 'all':
	for vector in vectors:
		for host in hosts:
			add_detect_task(host, vector['name'])
else:
	for vector in args['vectors'].split(","):
		for host in hosts:
			add_detect_task(host, vector)
# scanning
iterations = len(detect_tasks)
totalDoneStr = "(0/" + str(iterations) + ")"
print("Searching for open UDP applications " + totalDoneStr, flush=True, end='')
for i in range(iterations):
        backspace(len(totalDoneStr))

        iteration = i+1
        totalDoneStr = "(" + str(iteration) + "/" + str(iterations) + ")"

        print(totalDoneStr, flush=True, end='')
        scan_host(detect_tasks[-1], timeout)
        detect_tasks.pop()
print(f"\nFound {len(measure_tasks)} open UDP applications")
iterations = len(measure_tasks)
totalDoneStr = "(0/" + str(iterations) + ")"
print("Measuring UDP applications " + totalDoneStr, flush=True, end='')
for i in range(iterations):
        backspace(len(totalDoneStr))

        iteration = i+1
        totalDoneStr = "(" + str(iteration) + "/" + str(iterations) + ")"

        print(totalDoneStr, flush=True, end='')
        measure_host(measure_tasks[-1], timeout)
        measure_tasks.pop()
print("\n")
result_human = "Host	Port	Vector		Failed	Amp	Latency\n_______________________________________________________\n"
for result in results:
	result_human = result_human + str(result["host"]) + "	" + str(result["port"]) + "	" + str(result["name"]) + "		" + str(result["hitrate"]) + "	" + str(result["amp_factor"]) + "x	" + str(result["latency"]) + "ms\n"
print(result_human)
