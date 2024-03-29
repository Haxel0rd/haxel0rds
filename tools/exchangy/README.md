## Exchangy v1.04 - Exchange Server version & patchlevel detection   
* Last updated: 02/2022, v1.03 => v1.04 (current, stable)
* Small bugfix for connections when using sidechannel


## What is this tool for?
This tool was made for 'BlackBox' Information gathering puproses (i.e. when performing Pentests) to quickly identify the version and even patchlevel of a Microsoft Exchange Server. The tool comes with some bypass mechanisms and features to detect even hardened targets (e.g.: Firewalls, cleansed owa panels, etc.). You can run this tool from remote and you do NOT need to be authenticated on the target Server. 


* Detecs almost all Exchange Server Versions!
* Works: remote / unauthenticated / BlackBox point of view
* Requires: Exchange Server running at target ip or domain
* Made for longterm stability! Has own internal database
* Tested with: Win / Linux / py3.7.0 (only native libs)
* Works for targets with SSL/TLS even in older versions
* Failchecks and different detection mechanisms
* Can bypass some firewall protection mechanisms
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
                      skips database updates (updates for the tool itself must be done by manual download)
* enter buildno:      python3 exchangy.py -e    
                      in enter mode, no requests to a target are being made, the number 
                      is entered manually and then looked up in the tools internal database
<br />


## Not included (maybe in the future):
* CVE awareness: show if s server is vulnerable. But i dropped on this as i don't have the time 
  maintain a list of Exchange related CVE's (ontop of updates for new exchange patchlevels)
* Quiet-mode: only output either the detected version or error (in JSON format)
  This was meant for better framework integration, but on the other hand it shouldn't be a big deal for a 
  dev to 'grep' from current/more chatty output (hint: errors always start like ">> ERROR: ", without quotes)
<br />


## About
* Version: v1.04
* Released: 02/2022
* Author: Haxel0rd
* BUG REPORTS TO: twitter.com/haxel0rd
* Published under the GNU General Public Licence v3
* State: actively updating detections, fixing major/breaking bugs
* Changelog v1.02: Now covering SU Updates! Also: Bugfixes and improvements (fixed update logic, improved 
  networking and connections, improved detection, etc.)
* Changelog v1.01: recoded, better core, improved detections, now running with internal db, improved bypasses,
  detection updater, show new tool version, target online probes, new modes (skip online checks, skip updates, 
  manual enter mode), improved error handling, several bugfixes, code tidied up and commented.
* Check tools header comment-section for additional infos (i.e. regarding non-supported weak SSL/TLS ciphers)
<br />


May the force be with you.
