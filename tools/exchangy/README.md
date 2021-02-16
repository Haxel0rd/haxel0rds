## Exchangy - Exchange Server version & patchlevel detection   
* Version: v1.01 
* RECODED! now made for longterm stability! New core, new internal database (now independant from msdocs), updater, etc. 
* NEW features: detections updater, hint a new tool version, target online-checks, manual enter mode, bugfixes, improved errorhandling, etc. 
* Requires: Exchange with OWA to run at target
* Works: remote / unauthenticated / (BlackBox view)
* Tested with: Win / Linux / py3.7.0 (only native libs)
* Supports: from Exchange Server 5.0 up to 2019 (and upwards)
* Works for targets with SSL/TLS even in older versions
* Failchecks and different detection mechanisms
* Can deal with cleaned and customized panels
* Run the tool with -h to display help page.
<br />

## How to use (examples):
* basic:              python3 exchangy.py 
* help page:          python3 exchangy.py -h
* set target:         python3 exchangy.py -t mail.someserver.com
* set custom port:    python3 exchangy.py -t mail.someserver.com -p 8443
* This works also: <br />
python3 exchangy.py -t https://mail.someserver.com/someurl/cutoff/fi .. <br />
(the tool uses base url and discards the leftover, so you can paste full or partial url for more comfort)
* or this <br />
python3 exchangy.py -t 127.0.0.1:3301/foo/bar
* skip online probe:  python3 exchangy.py -s
* skip (db) update:   python3 exchangy.py -u    
  // skips database updates (updates for tool must be done by manual download anyways)
* enter buildno:      python3 exchangy.py -e    
  // (in enter mode, no requests to a target are being made, the number is <br />entered manually and then looked up in the tools internal database)
<br />

## About
* Version: v1.01
* Released: 02/2021
* Author: Haxel0rd
* Published under the GNU General Public Licence v3
* BUG REPORTS TO: twitter.com/haxel0rd
* Changelog v1.1: recoded, better core, improved detections, now running with internal db, improved bypasses, <br />  detection updater, show new tool version, target online probes, new modes (skip onlie, skip updates, enter mode),<br />   improved error handling, several bugfixes, coded tidy-up
<br />

May the force be with you.


