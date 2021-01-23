## BRB (rework in almost done), check back in a few days...

## Exchangy - Exchange Server version & patchlevel detection   
* Requires: OWA to run at target!
* Works: remote / unauthenticated / (BlackBox view)
* CrossCompatibilty: Win / Linux / py2.7 / py3.7 
* Supports: from Exchange Server 2000 up to 2019
* Works for targets with SSL/TLS in any version
* Several failchecks and detection mechanisms
<br />

## How to use:
* Example 1: python3 exchangy.py 
* Example 1: python3 exchangy.py -h
* Example 2: python3 exchangy.py -t mail.someserver.com
* Example 2: python3 exchangy.py -t mail.someserver.com -p 8443
* This works also: <br />
python3 exchangy.py -t https://mail.someserver.com/someurl/cutoff/fi .. <br />
(the tool uses base url and discards the leftover, so you can paste full or partial url for more comfort)
<br />

## About
* Version: v1.00
* Created: 06/2020
* Author: Haxel0rd
* Published under the GNU General Public Licence v3
* BUG REPORTS TO: twitter.com/haxel0rd
<br />

May the force be with you.
