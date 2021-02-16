## Exchangy v1.01 - Exchange Server version & patchlevel detection   
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
* This works also:    python3 exchangy.py -t https://mail.someserver.com/someurl/cutoff/fi ..
                      (the tool uses base url and discards the leftover, so you can paste full or partial url for more comfort)
* Another example:    python3 exchangy.py -t 127.0.0.1:3301/foo/bar
* skip online probe:  python3 exchangy.py -s
                      skips the "is target online?" checks
* skip (db) update:   python3 exchangy.py -u    
                      skips database updates (updates for tool must be done by manual download anyways)
* enter buildno:      python3 exchangy.py -e    
                      in enter mode, no requests to a target are being made, the number 
                      is entered manually and then looked up in the tools internal database
<br />

## Not included (maybe in the future):
* CVE awareness: show if server is vulnerable, but i don't have the time 
  maintain a list of Echange related CVE's (ontop of updates for new exchange patchlevels)
* Quiet-mode: only output either the detected version or error (in JSON format)
  This was meant for better framework integration, but on the other hand it shouldn't be a big deal for a 
  dev to 'grep' from current/more chatty output (hint: errors always start like ">> ERROR: ", without quotes)
* In manual enter mode (-e), add optional feeding of the number like -e 1.22.333, but this wasn't implemented.
<br />

## About
* Version: v1.01
* Released: 02/2021
* Author: Haxel0rd
* Published under the GNU General Public Licence v3
* BUG REPORTS TO: twitter.com/haxel0rd
* State: actively updating detections, 
  fixing major/breaking bugs and those that dont require 
  too much time investment (dont want to touch depper parts of the code). Atm not planed to add new features.
* Changelog v1.1: recoded, better core, improved detections, now running with internal db, improved bypasses,
  detection updater, show new tool version, target online probes, new modes (skip online checks, skip updates, 
  manual enter mode), improved error handling, several bugfixes, code tidied up and commented.
* Check tools header comment-section for additional infos (i.e. regarding non-supported weak SSL/TLS ciphers)
<br />

May the force be with you.
