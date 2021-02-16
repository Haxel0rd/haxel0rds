## Exchangy - Exchange Server version & patchlevel detection   
* REWORKED! New core that is made for longterm stability
* Version: v1.00 (before was beta)
* Requires: Exchange with OWA to run at target
* Works: remote / unauthenticated / (BlackBox view)
* Tested with: Win / Linux / py3.7.0, no additonal libs
* Supports: from Exchange Server 5.0 up to 2019 (and upwards)
* Works for targets with SSL/TLS in any version
* Failchecks and different detection mechanisms
* NEW features: STABILITY! The beta version broke and was unreliable, new version now has own internal db for detections!
* NEW features: detections updater, hint new tool version, online-checks, manual entering mode, bugfixes, improved errorhandling, etc. 
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
  // skips database updates (updates for tool must be done by manual download ayways)
* enter buildno:      python3 exchangy.py -e    
  // (in enter mode, no requests to a target are being made, the number is <br />entered manually and then looked up in the tools internal database)
* in the end i thought of a quiet (-q) mode that only outputs only the version in JSON format (for better integration into frameworks), but this idea
  came up to late- the recoding was done and i wanted to move on to other projects. But in the end, a dev can also simply "grep" the numbers from tools 
  output and put it into his own prefered format, this shouldn't be a big deal at all.
<br />

## About
* Version: v1.00
* Released: 02/2021
* Author: Haxel0rd
* Published under the GNU General Public Licence v3
* BUG REPORTS TO: twitter.com/haxel0rd
<br />

May the force be with you.


