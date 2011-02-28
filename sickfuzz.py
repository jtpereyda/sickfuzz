#!/usr/bin/env python
# Author: sickness
# Hope you like it
# For any bugs/suggestions contact sick.n3ss416@gmail.com
import sys,subprocess,time,os,signal,socket,getopt
from time import sleep,localtime,strftime
#-------------------------------------------------------------------------------
spike = ""
fpath = ""
script = ""
ip = ""
port = ""
iface = ""
log = ""
#-------------------------------------------------------------------------------
def help_screen():
	print "                  __             ___                           "
	print "       __        /\ \          /'___\                          "
	print "  ____/\_\    ___\ \ \/'\     /\ \__/  __  __  ____    ____    "
	print " /',__\/\ \  /'___\ \ , <     \ \ ,__\/\ \/\ \/\_ ,`\ /\_ ,`\  "
	print "/\__, `\ \ \/\ \__/\ \ \\`\    \ \ \_/\ \ \_\ \/_/  /_\/_/  /_ "
	print "\/\____/\ \_\ \____\\ \_\ \_\   \ \_\  \ \____/ /\____\ /\____\ "
	print " \/___/  \/_/\/____/ \/_/\/_/    \/_/   \/___/  \/____/ \/____/\n\n"
	print "  Welcome to sickfuzz version 0.1"
	print "  Codename: 'Have you g0tmi1k!?'"
	print "  Author: sickness"
	print "  Bug reports or suggestions at: sick.n3ss416@gmail.com\n"
	print "  Usage example:"
	print "  ./sickfuzz.py --spike /pentest/fuzzers/spike/ --fpath /root/sickfuzz/ --script all --ip 192.168.1.64 --port 80 --iface wlan0 --log /root/"+"\n"
	print "  IMPORTANT: DO NOT USE THE pcap_logs DIRECTORY TO SAVE LOGS from --log !!!\n"
	print "	--help/-h  - prints this help menu."
	print "	--spike/-s <path to spike folder>"
	print "	--fpath/-f <path to the fuzzer>"
	print " 	--script/-c <[all]/[number]> use --script-show to view available scripts"
	print "	--ip/-t <target ip>"
	print "	--port/-p <target port>"
	print " 	--iface/-i <network interface>"
	print "	--log/-l <path where .pcap log files will be saved>\n"
	
def clean_up():
	print " [>] Stopping fuzzing and tshark ..."
	os.kill(tshark.pid,signal.SIGTERM)
	print "Splitting .pcap files"
	subprocess.Popen("editcap -c 10000 "+fpath+"pcap_logs/fuzzing_log.pcap"+" "+fpath+"pcap_logs/logs.pcap",shell=True).wait()
	subprocess.Popen("mv -f "+fpath+"pcap_logs/*"+" "+log,shell=True).wait()
	subprocess.Popen("rm -rf "+fpath+"pcap_logs/*",shell=True).wait()
	subprocess.Popen("rm -rf "+fpath+"spike_log.txt",shell=True).wait()
	print " [>] Done!\n"
#-------------------------------------------------------------------------------	
if len(sys.argv) == 1:
	help_screen()
	sys.exit()
else:
	pass
if sys.argv[1] == "--help":
	help_screen()
	sys.exit()
else:
	pass
if sys.argv[1] == "--script-show":
	print "  1/12: Fuzzing GET /"
	print "  2/12: Fuzzing GET /abc="
	print "  3/12: Fuzzing HEAD /"
	print "  4/12: Fuzzing POST /"
	print "  5/12: Fuzzing GET / HTTP/1.1"
	print "  6/11: Fuzzing HEAD / HTTP/1.1"
	print "  7/12: Fuzzing POST / HTTP/1.1"
	print "  8/12: Fuzzing Authorization:"
	print "  9/12: Fuzzing Content-Length:"
	print "  10/12: Fuzzing If-Modified-Since:"
	print "  11/12: Fuzzing Connection:"
	print "  12/12: Fuzzing X-a:"
	sys.exit()
else:
	pass
if sys.argv[1] == "-c-show":
	print "  1/12: Fuzzing GET /"
	print "  2/12: Fuzzing GET /abc="
	print "  3/12: Fuzzing HEAD /"
	print "  4/12: Fuzzing POST /"
	print "  5/12: Fuzzing GET / HTTP/1.1"
	print "  6/11: Fuzzing HEAD / HTTP/1.1"
	print "  7/12: Fuzzing POST / HTTP/1.1"
	print "  8/12: Fuzzing Authorization:"
	print "  9/12: Fuzzing Content-Length:"
	print "  10/12: Fuzzing If-Modified-Since:"
	print "  11/12: Fuzzing Connection:"
	print "  12/12: Fuzzing X-a:"
	sys.exit()
else:
	pass
try:
    opts, args = getopt.getopt(sys.argv[1:], "s:f:c:t:p:i:l:h?", ["spike=","fpath=","script=","ip=","port=","iface=", "log=","help"])
except getopt.GetoptError, err:
	help_screen()
	sys.exit()
for o, a in opts:
	if o in ("-s", "--spike"):
		spike = a
	if o in ("-f", "--fpath"):
	        fpath = a
	if o in ("-c", "--script"):
		script = a
	if o in ("-t", "--ip"):
		ip = a
	if o in ("-p", "--port"):
		port = a
	if o in ("-i", "--iface"):
		iface = a
	if o in ("-l", "--log"):
		log = a
	if o in ("-h", "--help", "-?"):
		help_screen()
		sys.exit()
try:
	fuzzer = "./generic_send_tcp"
	scripts = ["HTTP/web00.spk","HTTP/web01.spk","HTTP/web02.spk","HTTP/web03.spk","HTTP/web04.spk","HTTP/web05.spk","HTTP/web06.spk","HTTP/web07.spk","HTTP/web08.spk","HTTP/web09.spk","HTTP/web10.spk","HTTP/web11.spk"]
	skipv = "0 0"
	
	if spike == "" : print "Missing \"--spike/-s\", check --help for more info.\n" ; sys.exit()
	if fpath == "" : print "Missing \"--fpath/-f\", check --help for more info.\n" ; sys.exit()
	if script == "" : print "Missing \"--script/-c\", check --help for more info.\n" ; sys.exit()
	if ip == "" : print "Missing \"--ip/-t\", check --help for more info.\n" ; sys.exit()
	if port == "" : print "Missing \"--port/-p\", check --help for more info.\n" ; sys.exit()
	if iface == "" : print "Missing \"--iface/-i\", check --help for more info.\n" ; sys.exit()
	if log == "" : print "Missing \"--log/-l\", check --help for more info.\n"; sys.exit()
	
	def openport():
		s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		try:
			s.connect((ip,int(port)))
			s.shutdown(2)
			return True
		except:
			return False

	def path_fix():
		spike_path = sys.argv[3]
		fuzz_path = sys.argv[5]
		spike_path = spike_path.rstrip("/")+"/"
		fuzz_path = fuzz_path.rstrip("/")+"/"
	path_fix()
	
	print " [>] Starting: sickfuzz v0.1 "
	if openport() == True:
		pass
	else:
		print "Could not connect, check if the port is opened!"
		sys.exit()
	print " [>] Launching packet capture, please wait ..."
	sleep(2)
	try:
		tshark = subprocess.Popen("tshark -i "+iface+" -d tcp.port=="+port+",http -w "+fpath+"pcap_logs/fuzzing_log.pcap -q",shell=True)
		print " [>] Capturing packets, now starting to fuzz!\r"
		sleep(2)
	except KeyboardInterrupt:
		print " [>] Something went wrong!"
		print "Exiting ..."
		sys.exit()

	start = time.clock()
	print " [>] Fuzzing starting at "+strftime("%a, %d %b %Y %H:%M:%S", localtime())+", stand back!\n"
	sleep(2)
	def web00():
		print "1/12: Fuzzing GET /"
		subprocess.Popen("export LD_LIBRARY_PATH=. && cd "+spike+"&&"+fuzzer+" "+ip+" "+port+" "+fpath+scripts[0]+" "+skipv+" > "+fpath+"spike_log.txt",shell=True).wait()
		print "GET / finished, moving to next script ...\n"
		sleep(5)
	def web01():
		print "2/12: Fuzzing GET /abc="
		try:
			subprocess.Popen("export LD_LIBRARY_PATH=. && cd "+spike+"&&"+fuzzer+" "+ip+" "+port+" "+fpath+scripts[1]+" "+skipv+" > "+fpath+"spike_log.txt",shell=True).wait()
		except KeyboardInterrupt:
			openport()
		print "GET /abc= finished, moving to next script ...\n"
		sleep(5)
	def web02():
		print "3/12: Fuzzing HEAD /"
		try:
			subprocess.Popen("export LD_LIBRARY_PATH=. && cd "+spike+"&&"+fuzzer+" "+ip+" "+port+" "+fpath+scripts[2]+" "+skipv+" > "+fpath+"spike_log.txt",shell=True).wait()
		except KeyboardInterrupt:
			openport()
		print "HEAD / finished, moving to next script ...\n"
		sleep(5)
	def web03():
		print "4/12: Fuzzing POST /"
		try:
			subprocess.Popen("export LD_LIBRARY_PATH=. && cd "+spike+"&&"+fuzzer+" "+ip+" "+port+" "+fpath+scripts[3]+" "+skipv+" > "+fpath+"spike_log.txt",shell=True).wait()
		except KeyboardInterrupt:
			openport()
		print "POST / finished, moving to next script ...\n"
		sleep(5)
	def web04():
		print "5/12: Fuzzing GET / HTTP/1.1"
		subprocess.Popen("export LD_LIBRARY_PATH=. && cd "+spike+"&&"+fuzzer+" "+ip+" "+port+" "+fpath+scripts[4]+" "+skipv+" > "+fpath+"spike_log.txt",shell=True).wait()
		print "GET / HTTP/1.1 finished, moving to next script ...\n"
		sleep(5)
	def web05():
		print "6/11: Fuzzing HEAD / HTTP/1.1"
		try:
			subprocess.Popen("export LD_LIBRARY_PATH=. && cd "+spike+"&&"+fuzzer+" "+ip+" "+port+" "+fpath+scripts[5]+" "+skipv+" > "+fpath+"spike_log.txt",shell=True).wait()
		except KeyboardInterrupt:
			openport()
		print "HEAD / HTTP/1.1 finished, moving to next script ...\n"
		sleep(5)
	def web06():
		print "7/12: Fuzzing POST / HTTP/1.1"
		try:
			subprocess.Popen("export LD_LIBRARY_PATH=. && cd "+spike+"&&"+fuzzer+" "+ip+" "+port+" "+fpath+scripts[6]+" "+skipv+" > "+fpath+"spike_log.txt",shell=True).wait()
		except KeyboardInterrupt:
			openport()
		print "POST / HTTP/1.1 finished, moving to next script ...\n"
		sleep(5)
	def web07():
		print "8/12: Fuzzing Authorization:"
		try:
			subprocess.Popen("export LD_LIBRARY_PATH=. && cd "+spike+"&&"+fuzzer+" "+ip+" "+port+" "+fpath+scripts[7]+" "+skipv+" > "+fpath+"spike_log.txt",shell=True).wait()
		except KeyboardInterrupt:
			openport()
		print "Authorization: finished, moving to next script ...\n"
		sleep(5)
	def web08():
		print "9/12: Fuzzing Content-Length:"
		try:
			subprocess.Popen("export LD_LIBRARY_PATH=. && cd "+spike+"&&"+fuzzer+" "+ip+" "+port+" "+fpath+scripts[8]+" "+skipv+" > "+fpath+"spike_log.txt",shell=True).wait()
		except KeyboardInterrupt:
			openport()
		print "Content-Length: finished, moving to next script ...\n"
		sleep(5)
	def web09():
		print "10/12: Fuzzing If-Modified-Since:"
		try:
			subprocess.Popen("export LD_LIBRARY_PATH=. && cd "+spike+"&&"+fuzzer+" "+ip+" "+port+" "+fpath+scripts[9]+" "+skipv+" > "+fpath+"spike_log.txt",shell=True).wait()
		except KeyboardInterrupt:
			openport()
		print "If-Modified-Since: finished, moving to next script ...\n"
		sleep(5)
	def web10():
		print "11/12: Fuzzing Connection:"
		try:
			subprocess.Popen("export LD_LIBRARY_PATH=. && cd "+spike+"&&"+fuzzer+" "+ip+" "+port+" "+fpath+scripts[10]+" "+skipv+" > "+fpath+"spike_log.txt",shell=True).wait()
		except KeyboardInterrupt:
			openport()
		print "Connection: finished, moving to next script ...\n"
		sleep(5)
	def web11():
		print "12/12: Fuzzing X-a:"
		try:
			subprocess.Popen("export LD_LIBRARY_PATH=. && cd "+spike+"&&"+fuzzer+" "+ip+" "+port+" "+fpath+scripts[11]+" "+skipv+" > "+fpath+"spike_log.txt",shell=True).wait()
		except KeyboardInterrupt:
			openport()
		print "X-a: finished, moving to next script ...\n"
		sleep(5)

	if script == "all":
		if openport() == True:
			web00()
		else:
			print "\n"
			print " [>] We have a crash!!"
			print "\n"
			clean_up()
			sys.exit()
		if openport() == True:
			web01()
		else:
			print "\n"
			print " [>] We have a crash!!"
			print "\n"
			clean_up()
			sys.exit()
		if openport() == True:
			web02()
		else:
			print "\n"
			print " [>] We have a crash!!"
			print "\n"
			clean_up()
			sys.exit()
		if openport() == True:
			web03()
		else:
			print "\n"
			print " [>] We have a crash!!"
			print "\n"
			clean_up()
			sys.exit()
		if openport() == True:
			web04()
		else:
			print "\n"
			print " [>] We have a crash!!"
			print "\n"
			clean_up()
			sys.exit()
		if openport() == True:
			web05()
		else:
			print "\n"
			print " [>] We have a crash!!"
			print "\n"
			clean_up()
			sys.exit()
		if openport() == True:
			web06()
		else:
			print "\n"
			print " [>] We have a crash!!"
			print "\n"
			clean_up()
			sys.exit()
		if openport() == True:
			web07()
		else:
			print "\n"
			print " [>] We have a crash!!"
			print "\n"
			clean_up()
			sys.exit()
		if openport() == True:
			web08()
		else:
			print "\n"
			print " [>] We have a crash!!"
			print "\n"
			clean_up()
			sys.exit()
		if openport() == True:
			web09()
		else:
			print "\n"
			print " [>] We have a crash!!"
			print "\n"
			clean_up()
			sys.exit()
		if openport() == True:
			web10()
		else:
			print "\n"
			print " [>] We have a crash!!"
			print "\n"
			clean_up()
			sys.exit()
		if openport() == True:
			web11()
		else:
			print "\n"
			print " [>] We have a crash!!"
			print "\n"
			clean_up()
			sys.exit()	
	elif script == "1":
		web00()
		print "\n"
		clean_up()
		sys.exit()
	elif script == "2":
		web01()
		print "\n"
		clean_up()
		sys.exit()
	elif script == "3":
		web02()
		print "\n"
		clean_up()
		sys.exit()
	elif script == "4":
		web03()
		print "\n"
		clean_up()
		sys.exit()
	elif script == "5":
		web04()
		print "\n"
		clean_up()
		sys.exit()
	elif script == "6":
		web05()
		print "\n"
		clean_up()
		sys.exit()
	elif script == "7":
		web06()
		print "\n"
		clean_up()
		sys.exit()
	elif script == "8":
		web07()
		print "\n"
		clean_up()
		sys.exit()
	elif script == "9":
		web08()
		print "\n"
		clean_up()
		sys.exit()
	elif script == "10":
		web09()
		print "\n"
		clean_up()
		sys.exit()
	elif script == "11":
		web10()
		print "\n"
		clean_up()
		sys.exit()
	elif script == "12":
		web11()
		print "\n"
		clean_up()
		sys.exit()
	else:
		print "You have picked an invalid script."
		sys.exit()
	
	clean_up()
	end = time.clock()
	print " [>] Ending fuzzing at:"+strftime("%a, %d %b %Y %H:%M:%S", localtime())

#-------------------------------------------------------------------------------
except KeyboardInterrupt:
	print "\n"
	clean_up()
	sys.exit()