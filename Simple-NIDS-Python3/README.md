# Rulebase-NIDS
txt_file Rulebase Network Intrusion Detection System Written in Python with Scapy.

# README

1.Network Instruction Detectsino System works as follows:
	A.Read the txt format rules line by line and make Feautures from them using rule.py.
	B.Each rule is passed to the sniffer. Only packets that conform to the sniffer rule are sniffed.
	C.Sniffer packets through the run function of sniffer.py.
	D.Check if the packet satisfies the rule through sniffer.py. Then, if it is satisfied, it performs logging and
          outputting to the screen.
2.INSTALL 
	A.Install [python 3.x](https://www.python.org/downloads/) 
                  [scapy](http://scapy.readthedocs.io/en/latest/installation.html#installing-scapy-v2-x)
		A-1. $ git clone https://github.com/secdev/scapy.git
		A-2. $ cd scapy
		A-3. $ sudo python setup.py install 
	B.cd Simple-NIDS-Python3
3.To use this IDS, you must first have a text-based rule.txt file in snort format. And the rules.txt file should be in the rules directory.

# USAGE Command
4.sudo python3 -B src/SimpleNIDS.py rules/exampleRules.txt or sudo python3 -B src/SimpleNIDS.py [YOURDIRECTORY/YOURRULE.txt]
5.If you want to quit “ctrl+c”



