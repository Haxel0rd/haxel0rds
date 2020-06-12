# -*- coding: utf-8 -*-
##############################################################################
# Copyright (c) 2020 Haxel0rd                                                #
# Published under the GNU general Public Licence v3                          #
# See LICENCE File for more details: github.com/Haxel0rd/Exchangy            #
#                                                                            #
# BUG REPORTS:                                                               #
#   > Please send Bug reports to: twitter.com/haxel0rd                       #
#   > Thank you.                                                             #
#                                                                            #
# ------------------------------------------------------------               #
# Exchangy - Exchange Server version & patchlevel detection                  #
# ------------------------------------------------------------               #
# - Works: Remote / unauthicated / (BlackBox view)                           #
# - Requires: OWA to run at target, fetches OWA build, then compares         #
#   buildnumber with MS-docs. Patchlevel does not detect KB patches!         #
#   Supported Patchlevels are:                                               #
#   ServicePack (SP), CumulativeUpdates (CU) and RollupUpdates (RU).         #
# - Cross Compatibilty: Win, Linux / py2 & py3 (tested: 2.7.13 & 3.7.0)      #
# - Supports: Exchange 20XX down to Exchange 2000, SSL/TLS in any version    #
# - Type: Exchange module of private framework, isolated as single tool      #
# - CreationDate: 06/2020, version: v1.00                                    #
#                                                                            #
##############################################################################

import re
import sys
import ssl
import getopt
import socket

# --- Packetz --- #
owa_packet = 'GET /owa/auth/logon.aspx HTTP/1.1\r\nHost: {{target}}\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: identity\r\nUpgrade-Insecure-Requests: 1\r\nConnection: close\r\nDNT: 1\r\n\r\n'
xch_packet = 'GET /en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019 HTTP/1.1\r\nHost: docs.microsoft.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: identity\r\nUpgrade-Insecure-Requests: 1\r\nConnection: close\r\nDNT: 1\r\n\r\n'
# --- Packetz --- #

# Start tool, show Banner
def intro():
    print('\n\n####################################################')
    print('#                                                  #')
    print('#     ____            __                           #')
    print('#    / __/__ __ ____ / /  ___ _ ___  ___ _ __ __   #')
    print('#   / _/  \ \ // __// _ \/ _ `// _ \/ _ `// // /   #')
    print('#  /___/ /_\_\ \__//_//_/\_,_//_//_/\_, / \_, /    #')
    print('#                            v1.00 /___/ /___/     #')
    print('#                                                  #')
    print('#  Exchange Server version & patchlevel detection  #')
    print('#    Coded by Haxel0rd - (twitter.com/haxel0rd)    #')
    print('#                                                  #')
    print('####################################################\n\n')

# Check if program was called with option args
def parse_args():
    opthalp = 0
    opttrgt = ''
    optport = ''
    ## Check args
    try:
        opts,args = getopt.getopt(sys.argv[1:],'t:p:h')
    except:
        print('** Error: something went wrong with the options provided.')
        sys.exit('** Can not continue, exiting.\n')
    for opt, arg in opts:
        if opt in ('-h'):
            opthalp = 1
        if opt in ('-t'):
            opttrgt = arg
        if opt in ('-p'):
            optport = arg
    return opthalp, opttrgt, optport

# Onload operations, preapring checks
def onload():
    intro()
    target = ''
    options = parse_args()
    opthalp = options[0]
    opttrgt = options[1]
    optport = options[2]
    # Check if help was called
    if (opthalp != 0):
        print('** Printing halp page')
        print('** Exchangy (v1.0) - ')
        print('   Exchange Server version & patchlevel detection')
        print('   -------------------------------------------------')
        print('   -h    get help (basically this)')
        print('   -t    optional: set target to OWA: mail.url.com')
        print('   -p    optional: set custom port (default is 443)')
        print('   -------------------------------------------------')
        print('** Bug reports to: twitter.com/haxel0rd')
        print('** Halp delivered,')
        print('** Exiting.')
        print('\n\n')
        sys.exit()
    # Drop initialize msg
    print('** Initializing ...')
    # Check if target given, if not prompt user, then parse target
    if (options[1] == ''):
        target = input('** Set target: ')
    else:
        target = options[1]
    target = target.replace('http://','')
    target = target.replace('https://','')
    try:
        target = target.split(':')[0]
        target = target.split('/')[0]
    except:
        print('** Error: target seems malformed')
        sys.exit('** Cannot continue, exiting.\n')
    print('** Target set to:  '+target)
    # Check if custom port was given (else, default to 443)
    if (optport == ''):
        print('** Port   set to:  443 (default fallback)')
        port = 443
    else:
        try:
            port = int(optport)
        except:
            print('** Error: malformed port, must be number')
            sys.exit('** Cannot continue, exiting.\n')
        print('** Port   set to: '+str(optport))
        if (port > 65535 or port < 1):
            print('** Error: port must range between 1-65535.')
            sys.exit('** Cannot continue, exiting.\n')
    # All configuration is done now, initialize checks...
    initialize(target,port)

# Initialize checks, do actual infogathering on target and print results
def initialize(target,port):
    print('** Sending probes to check the targets services')
    xch = ''
    owa = ''
    rls = ''
    plv = ''
    host = (target,port)
    incomplete = 0
    err_reason = 'unknown'
    packet = owa_packet.replace('{{target}}',target)
    owa_response = sendpacket(host,packet)
    owa_regex = ''
    # Fetch OWA buildnumber, we need this to get the Exchange version
    if (owa_response == ''):
        print('** Error: unable to fetch data from target')
        print('   make sure the target was set correctly.')
        sys.exit('** Cannot continue, exiting.\n')
    else:
        owa_confirmed = False
        owa_regex = re.search('<!-- OwaPage = ASP\.auth_logon_aspx -->',str(owa_response))
        owa_regex2 = re.search('/owa/',str(owa_response))
        if owa_regex:
            owa_confirmed = True
            print('** Found OWA panel, looking for buildnumber')
        if (owa_regex2 and owa_confirmed == False):
            print('** Maybe dealing with OWA panel, sending more checks')
        owa_regex = re.search('\"/owa/(auth/|)[0-9]{1,}\.[0-9]{1}\.[0-9]{3,}(.{1,}|)/themes/',str(owa_response))
    if not owa_regex:
        # Something did not work out, fire a second round with different url
        # (the admins may have cleansed the OWA panel, we try to bypass this with internal Server error page)
        if (owa_confirmed == True):
            print('** Failed fetching OWA version, panel may have')
            print('   been "cleansed" by admins.. trying to bypass')
        else:
            print('** Nothing found yet, retrying with different approach')
        packet = packet.replace('/owa/auth/logon.aspx','https://'+str(host[0])+'/owa/auth/errorfe.aspx') # Intentionally added full url for this 2nd try request
        owa_response = sendpacket(host,packet)
        owa_regex = re.search('\"/owa/(auth/|)[0-9]{1,}\.[0-9]{1}\.[0-9]{3,}(.{1,}|)/themes/',str(owa_response))
        if not owa_regex and owa_confirmed == True:
            print('** Unable to find buildnumber.')
            sys.exit('** Cannot continue, exiting.\n')
        if not owa_regex:
            print('** Unable to find OWA at target server :( ')
            sys.exit('** Cannot continue, exiting.\n')
    owa_regex = str(owa_regex.group()).split('/owa/')[1]
    owa_regex = str(owa_regex.split('/themes/')[0])
    if (owa_regex[0:5]) == 'auth/':
        owa_regex = owa_regex[5:]
    owa = owa_regex
    print('** OWA version found, trying Exchange version next')
    # Fetch Exchange version and patchlevel
    packet = xch_packet
    mshost = ('docs.microsoft.com',443)
    xch_response = sendpacket(mshost,packet)
    xch_regex = ''
    if (xch_response != ''):
        xch_response = xch_response.replace('\\r','').replace('\\n','').replace('\r','').replace('\n','')
        xch_regex = re.search('Build number \(long format\)<\/strong><\/th><\/tr><\/thead><tbody>.+',str(xch_response),re.MULTILINE|re.DOTALL)
    if not xch_regex:
        print('** Failed fetching Exchange Server version :( ')
        xch = '<unknown>'
        rls = '<unknown>'
    else:
        xch_regex = str(xch_regex.group())
        xch_regex = str(re.search('<tr>(\n|)<td style=\"text-align: left;\">.{0,}<\/tr>',str(xch_response),re.DOTALL).group())
        if not xch_regex:
            print('** Failed fetching Exchange Server version :( ')
        else:
            xch_regex = xch_regex.split('</tr>')
            itemcount = len(xch_regex)
            passed = 1
            while passed < 3:
                for item in xch_regex:
                    if (passed == 1):
                        detect00r = re.search(owa_regex,item)
                    if (passed == 2):
                        incomplete = 1
                        err_reason = 'MS fault!'
                        detect00r = re.search(owa_regex[:6],item)
                    if detect00r:
                        itm = str(item).split('<td style="text-align: left;">')
                        xch = str(itm[1])[:-5]
                        rls = str(itm[2])[:-5]
                        passed = 3
                        if (xch[:9] == '<a href="'):
                            xch = xch.split('data-linktype=\"external\">')[1]
                            xch = xch.replace('</a>','').replace('</td>','').replace('</span>','')
                        break
                passed+=1
    plv_tmp = ''
    if (xch == ''):
        xch = '<unknown>'
        rls = '<unknown>'
    else:
        try:
            plv_tmp = str(xch.split('Exchange Server 20')[1][3:])
        except:
            pass
        xch = xch[:-len(plv_tmp)]
        if (re.search('Update Rollup',xch)):
            plv = plv_tmp+', '+xch.split(' for ')[0]
            xch = xch.split(' for ')[1]
        else:
            plv = plv_tmp
        if (plv == ''):
            plv = '<unknown>'
    if (incomplete == 1):
        xch = xch+plv_tmp
        plv = '<unreliable>'
        rls = '<unreliable>'
    
    # WE ARE DONE - PRINTING OUT RESULTS AND GTFO HERE LOL
    print('** Done, printing out gathered informations:')
    print('   ---------------------------------------------')
    print('   > Exchange version:  '+xch)
    print('   > Patchlevel:        '+plv)
    print('   > Release Date:      '+rls)
    print('   > OWA version:       '+owa)
    print('   ---------------------------------------------')
    if (xch == '<unknown>'):
        print('** Could not retrieve Exchange version ('+err_reason+')')
        print('** Use OWA buildnumber for manual research.')
    elif (xch != '<unknown>' and incomplete == 1):
        print('** Could not retrieve patchlevel status ('+err_reason+')')
        print('   Microsoft docs are missing some subversions.')
        print('** Use OWA buildnumber for manual research.')
    else:
        print('** All checks performed well, no problems occured')
    print('** Job done, exiting.\n\n')

# Networking operations
def sendpacket(host,packet):
    unfound = 1
    response = ''
    while unfound < 5:
        try:
            https = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if (unfound == 1):
                sock = ssl.wrap_socket(https, ssl_version=ssl.PROTOCOL_TLSv1_2)
            if (unfound == 2):
                sock = ssl.wrap_socket(https, ssl_version=ssl.PROTOCOL_TLSv1_1)
            if (unfound == 3):
                sock = ssl.wrap_socket(https, ssl_version=ssl.PROTOCOL_TLSv1)
            if (unfound == 4):
                sock = ssl.wrap_socket(https, ssl_version=ssl.PROTOCOL_SSLv23)
            sock.settimeout(12)
            sock.connect(host)
            sock.send(packet.encode("utf-8"))
            i = 0;
            e = 0;
            while i < 1337: # Limited rounds to prevent getting stuck in loops
                chunk = str(sock.recv(4096))
                response += chunk
                response = response.replace('\\r\\n','').replace('\r\n','')
                if re.search('</body></html>',str(response)) != None:
                    unfound = 5
                    break
                i+=1
                if (chunk == "b''"):
                    e+=1
                    if (e > 7):
                        unfound = 5
                        break
                if (i == 1337):
                    unfound = 5
                    break
        except socket.error:
            if (unfound == 1):
                print('** Failed, retrying with older SSL/TLS version(s)')
            unfound+=1
        except socket.timeout:
            print('** Error sending packet: timeouted (target online?)')
            sys.exit('** Cannot continue, exiting.\n')
    return response
    
# START PROGRAM
# --------------
onload()
# --------------