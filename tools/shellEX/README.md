## shellEX v1.0 - Hafnium vulneraribility & infection scanner
* Scans targets for CVE-2021-26855 & webshell infections
* i made the tool initially for internal use in our 
  company, when we had to mitigate Hafnium for 3000+ customers
* The tool was designed to work remote, from a 'BlackBox' point-of-view
* Tested with Python 3.7 (native install, no additional libs), on win/linux
* Not my best/cleanest code, but it did the job pretty well, so now releasing this to public
* Detecting over 90 different shell variants (first wave, week one after initial report from Microsoft)
* Multithreaded, built for Mass-Scanning purposes, you can easily apply a list with thousands of targets!!
* Requires URL (-t) or list of URLs (-i) to Mailgateway (i.e.: 'mail.company.com') or run on single target
* Many tweaking options! Includes different SSRF detection approach (default is the nmap way of checking)

* Almost no false/positives as the scanner has already implemented checks for this
* Smartscanning, saving requests and therefore unnecessary traffic to offline hosts
* Implemented Failchecks on function and target stability
* Creation: 03/2021, version: v1.0
* Run the tool -h for more info
* May the force be with you.
<br />

## How to use (examples):
* Example 1:          python3 shellEX.py -h
* Example 2:          python3 shellEX.py -t mail.company.com
* Example 3:          python3 shellEX.py -i targets.txt
* Example 4:          python3 shellEX.py -i targets.txt -o results.txt
* Example 5:          python3 shellEX.py -i targets.txt -o results.txt -x 100
* Example 6:          python3 shellEX.py -i targets.txt -o results.txt -a supp0rt2,shell2
* Example 7:          python3 shellEX.py -i targets.txt -o results.txt -a supp0rt2,shell2 -v -n -c 0.5 -f 50 -x 100
<br />

## Options and Tweaks
* (-h) halp page
* (-x) Threadnumber
* (-c) Scanning Timeout
* (-d  disable smart scanning)
* (-f) False/Positive threshold
* (-a) add custom shells for detection
* (-t) define single target (needs URL)
* (-i) define list of targets as input file
* (-o) define a file to write results output
* (-n) use NSA Servers as SSRF identifier (only for cowboys!)
* (-v) Run in verbose mode (will produce much more chatty output)
* (-p) set custom port (suited for single targets and rare situations)
* (-r) Switch to -remote- SSRF identifier (method-2, default is method-1 with local SSRF, like nmap does)
<br />

## About
* Version: v1.0
* Released: 03/2021
* BUG REPORTS TO: twitter.com/haxel0rd
* Published under the GNU General Public Licence v3
* State: tool comes as is, works well with current 'Hafnium state',
  so i may only fix breaking bugs (if any) or update detections based
  on how 'active' Hafnium will stay, and based on tool user numbers.
* Disclaimer: use the tool at your own risk - i am not responsible for any damage or illegal usage! 
  Make sure you know what you are doing and understand the applying law before using Hackertools. 
<br />

May the force be with you.
