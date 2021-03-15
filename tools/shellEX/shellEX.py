# -*- coding: utf-8 -*-
##############################################################################
# Copyright (c) 2021 Haxel0rd                                                #
# Published under the GNU general Public Licence v3                          #
# See LICENCE File for more details:                                         #
# https://github.com/Haxel0rd/haxel0rds/tree/master/tools/shellEX            #
#                                                                            #
# BUG REPORTS:                                                               #
#   > Please send Bug reports to: twitter.com/haxel0rd                       #
#   > (i see may this faster than on github). Thank you.                     #
#                                                                            #
# ------------------------------------------------------------               #
# shellEX - Exchange/Hafnium vulnerability & infection scanner               #
# ------------------------------------------------------------               #
# - Creation: 03/2021, version: v1.0                                         #
# - Tested with 3000+ targets on Python 3.7 (native libs), win/linux         #
# - Run the tool -h for more info                                            #
# - May the force be with you.                                               #
#                                                                            #
##############################################################################

import re
import sys
import ssl
import time
import getopt
import struct
import socket
import threading
from binascii import hexlify

tout=1
adds=[]
tnum=33
stack=0
port=443
NSA=False
target=''
verbose=0
results=[]
threadz=[]
unduped=[]
fplimit=40
settings=[]
skipOn=False
vulnscount=0
infections=0
itemscount=0
inputfile=''
outputfile=''
LocalSSRF=True
threadcounter=0
started = int(time.time())

# target failcheck/stable/behaviour controller
ctrlsh = ['../owa/auth/logon.aspx']
# basic wave-1 shells (no random names)
shellx = ['help.aspx','iisstart.aspx','discover.aspx','aspnet.aspx','document.aspx','healthcheck.aspx','one.aspx','web.aspx','aspnet_iisstart.aspx','aspnet_client.aspx','aspnet_www.aspx','error.aspx','errorEE.aspx','errorEEE.aspx','errorEW.aspx','errorFF.aspx','errorFS.aspx','0QWYSEXe.aspx','dEVpCLuP.aspx','supp0rt.aspx','load.aspx','shell.aspx','xx.aspx']
# additional shell names
shellp = ['OutlookEN.aspx','OutlookUS.aspx','OutlookRU.aspx','OutlookDE.aspx','exchange.aspx','aa.aspx','t.aspx','shellex.aspx','system_web.aspx','TimeoutLogout.aspx','web.aspx','RedirSuiteServerProxy.aspx','MultiUp.aspx','aspnettest.aspx','x.aspx','xx.aspx','cmd.aspx','HttpProxy.aspx','Server.aspx','logout.aspx','session.aspx','s.aspx','a.aspx','iispage.aspx','errorcheck.aspx','default1.aspx','aspnet_pages.aspx']
# sytem_web path, looks like random but in wave-1 there was a "fixed random", if this applies here too we may have chances for more catches
shells = ['system_web/TInpB9PE.aspx','system_web/4YCo0Zhg.aspx','system_web/4DRbBQwm.aspx','system_web/2YiFOPS0.aspx','system_web/2WEQCSKa.aspx','system_web/2sruqPUH.aspx','system_web/1zOaF9mX.aspx','system_web/1TVl2paz.aspx','system_web/1rlVmLg3.aspx','system_web/1FAD3YuH.aspx','system_web/1DOyENMK.aspx','system_web/0x9pzh86.aspx','system_web/0Dj4P6Sy.aspx','system_web/0cvxSJy9.aspx']
# shells in owa/.. path
shellw = ['../OAB/log.aspx','../owa/auth/log.aspx','../owa/auth/logg.aspx','../owa/auth/logging.aspx','../owa/auth/logout.aspx','../owa/auth/a.aspx','../owa/auth/log.aspx','../owa/auth/shel90.aspx','../owa/auth/shel2.aspx','../owa/auth/shel.aspx','../owa/auth/shell.aspx','../owa/auth/onel.aspx','../owa/auth/one.aspx','../owa/auth/errorPage.aspx','../owa/auth/errorPages.aspx','../owa/auth/fatal-erro.aspx','../owa/auth/fatal-error.aspx','../owa/auth/fatalError.aspx','../owa/auth/current/one1.aspx','../owa/auth/bob.aspx','../owa/auth/authhead.aspx','../owa/auth/shel.aspx','../owa/auth/signon.aspx','../owa/auth/OutlookEN.aspx','../owa/auth/OutlookZH.aspx','../owa/auth/OutlookUS.aspx','../owa/auth/OutlookRU.aspx','../owa/auth/OutlookDE.aspx','../owa/auth/8Lw7tAhF9i1pJnRo.aspx','../owa/auth/xclkmcfldfi948398430fdjkfdkj.aspx']
# all shells:
shellz = ctrlsh+shellx+shellp+shells+shellw 
# ctrlsh must be at first position in shellz array, 
# otherwise some logic will break later (line 350'ish around).
# Now the packets:
xprobe = 'GET /aspnet_client/{{shell}} HTTP/1.1\r\nHost: {{host}}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0\r\nAccept: text/html, application/xhtml+xml, */*\r\nAccept-Language: de-DE\r\nAccept-Encoding: gzip, deflate\r\nConnection: Keep-Alive\r\nDNT: 1\r\n\r\n'
yprobe = 'GET /owa/auth/vulnx.html HTTP/1.1\r\nHost: {{target}}\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko\r\nAccept: text/html, application/xhtml+xml, */*\r\nAccept-Language: de-DE\r\nAccept-Encoding: gzip, deflate\r\nCookie: X-AnonResource-Backend={{identifier}}/#~1;X-AnonResource=true;\r\nConnection: close\r\nDNT: 1\r\n\r\n'

def banner():
  print('\n\n###########################################')
  print('#                                         #')
  print('#     \'ShellEX\' for Exchange Server       #')
  print('#  (detects CVE-2021-26855 & infections)  #')
  print('#         by twitter.com/haxel0rd         #')
  print('#                                         #')
  print('###########################################\n\n')
  print('** Initializing ...')

banner()
# Check if python 3 is used, if not then exit
if sys.version_info[0] < 3:
  print('>> ERROR: must be run with python3 (3.7 was tested)')
  print('   Sorry we can\'t continue, exiting ...')
  sys.exit('** May the force be with you.\n\n')

def args():
# call args
  global shellx, target, port, inputfile, outputfile, verbose, tnum, tout, skipOn, fplimit, LocalSSRF, NSA, settings
  try:
    opts,args = getopt.getopt(sys.argv[1:],'a:p:t:i:o:x:c:f:rndvh')
  except:
    print('>> ERROR: something went wrong with the options provided')
    print('   Sorry we can\'t continue, exiting ...')
    sys.exit('** May the force be with you.\n\n')
  optfix = getopt.getopt(sys.argv[1:],'a:p:t:i:o:x:c:f:rndvh')
  if(re.search('-t',str(optfix)) != None and re.search('-i',str(optfix)) != None): 
  # ugly way to check this, but fixed bug quick
    print('>> ERROR: can\'t use options -t with -i together')
    print('   Sorry we can\'t continue, exiting ...')
    sys.exit('** May the force be with you.\n\n')
  if(re.search('-n',str(optfix)) != None and re.search('-r',str(optfix)) != None): 
    print('>> ERROR: can\'t use options -n with -r together')
    print('   Sorry we can\'t continue, exiting ...')
    sys.exit('** May the force be with you.\n\n')
  for opt, arg in opts:
    if opt in ('-a'):
      try:
        added = str(arg).split(',')
        for add in added:
          if(add[-5:]!='.aspx'):
            add = add+'.aspx'
          adds.append(add)
      except:
        adds.append(arg)
      shellx = adds + shellx
    if opt in ('-p'):
      try:
        p = int(arg)
        port = p
      except:
        print('>> ERROR: custom port must be number')
        print('   (falling back to default: 443')
    if opt in ('-t'):
      singleTarget = str(arg).replace('https://','').replace('http://','')
      try:
        singleTarget = str(singleTarget.split('/')[0])
      except:
        pass
      target = str(singleTarget)
    if opt in ('-i'):
      inputfile = arg
    if opt in ('-n'):
      NSA=True
      LocalSSRF = False
    if opt in ('-d'):
      skipOn = True
    if opt in ('-r'):
      LocalSSRF = False
    if opt in ('-f'):
      try:
        fplimit = int(arg)
      except:
        print('>> ERROR: must be number (i.e.: -f 25)')
        print('   (falling back to default: 40')
        tnum=42
    if opt in ('-x'):
      try:
        tnum = int(arg)
      except:
        print('>> ERROR: must be number (i.e.: -x 100)')
        print('   (falling back to default: 33')
        tnum=33
    if opt in ('-c'):
      choice=arg
      if not re.search('((?![0-9.]).)',choice):
        tout=float(choice)
      else:
        while re.search('((?![0-9.]).)',choice):
          print('>> ERROR: must be number (i.e.: -c 3)')
          choice = input('   please try again: ')
          if not re.search('((?![0-9.]).)',choice):
            tout=float(choice)
            break
    if opt in ('-o'):
      outputfile = arg
      switch = False # turned of the check if output file exists (the now's default will overwrite)
      if (switch == True):
        firstrun = True
        passed = False
        while passed != True:
          if firstrun:
            pass
          else:
            print('>> ERROR: output file exists or readonly permissions')
            outputfile = input('   Please chose a different name: ')
          try:
            fileexists = open(outputfile,'r')
            fileexists.read()
            fileexists.close()
            passed = False
          except:
            passed = True
          firstrun = False
    if opt in ('-v'):
      verbose = 1
    if opt in ('-h'):
      print('** Printing halp page:')
      print('** ShellEX for Exchange (v1.0)')
      print('   ===========================')
      print('   Info: this tool will scan for webshell infections and')
      print('         checks if given targets are vulnerable to CVE-2021-26855')
      print('   ----------------------------------------------------------------')
      print('      .. options with dots expect input')
      print('   -a .. Add custom shellnames to scan, i.e.:')
      print('         -a supp0rt2,suspicious (.aspx not needed)')
      print('   -p .. Set a custom port (default is 443)')
      print('   -t .. Set a single target (i.e.: mail.company.com')
      print('   -i .. Set an input file for multiple targets (tested with 3000+)')
      print('         (one target url per line)')
      print('   -o .. Write output to file (-o file.txt)')
      print('   -x .. Multithreading (default=33 threads)')
      print('   -c .. Connection timeouts (default=1s, more=slower)')
      print('         upper if you have bad ping, lower if you have a good ping')
      print('   -f .. False/Posive threshold (default=40,recommended)')
      print('         setting this to 999 will completely turn of F/P detection')
      print('   -d    Disable smart scanning: this will ignore the results')
      print('         of target online-probes, but increase scanning time')
      print('   -r    Enable remote SSRF identifiers (this may grab a few more')
      print('         results (only a few, as seen in dev-tests with 3000+ targets)')
      print('   -n    Same as -r, but using NSA Website as SSRF identifier,')
      print('         not a problem unless you use this option with 1000+ targets')
      print('   -v    Verbose, display even if not infected')
      print('         Displays offline targets, False/Positives, (etc.)')
      print('         Targets with 500 or 200 are infected: 200(!) means')
      print('         the shell is active and can receive remote commands')
      print('         any time! Note: this option will produce large output!)')
      print('   -h    Display halp page (basically this)')
      print('   ----------------------------------------------------------------')
      print('>> WARNING:') 
      print('     do not try to \'clean\' a host that was marked as infected!')
      print('     Once a target was identified as infected, it\'s integrity can not be')
      print('     guaranteed anymore! Even if it \'looks\' clean, it requires a fresh')
      print('     Exchange install from scratch! Reset all Domain passwords and check')
      print('     other hosts in the same network for any additionally occuring attacks!')
      print('** DO NOT FULLY RELY ON THIS TOOL! IT MAY ONLY DETECT EARLIER VARIANTS.')
      print('   Shellnames are from first attack waves (1st week after MS-Blogpost,')
      print('   later variants may have different names / paths / behaviour!')
      print('   > The Tests for CVE-2021-26855 are reliable though as they actually')
      print('     exploit the SSRF (in a harmless way) and results are pretty precise.')
      print('** A rare number of Exchange servers was seen to respond unstable which in')
      print('   testing phase lead to unstable results (for about 1 from ~ 30 infected')
      print('   targets), re-run the tool 5-7 times if you want to catch even this case.')
      print('** Tool comes as is, did NOT run through full QA chain as it was imediate')
      print('   but we used this to successfully mitigate attacks for 3000+ customers.')
      print('** You can send Bug reports to: twitter.com/haxel0rd')
      print('   Tested on win/linux with py3.7 (native libs)')
      sys.exit('** May the force be with you.\n\n')
  print('   Use -h to output halp page...')
  print('** MAY ONLY DETECT EARLIER VARIANTS - DO NOT RELY ON THIS TOOL!')
  print('   Shellnames are from first attack waves (1st days after MS-Blogpost,')
  print('   later variants may have different names / paths / behaviour!')
  print('   (vulnerability detections are precise though, but carefull with -c !)')
  print('** Currently detecting '+str(len(shellz))+' different webshells')
  if target:
    settings.append('** Target set to: '+str(target)+'\n')
  if(port!=443):
    settings.append('** Port set to:   '+str(port)+'\n')
  if(tnum!=33):
    settings.append('** Multithreading set to '+str(tnum)+' threads\n')
  if(tout!=1):
    settings.append('** Using modified value for connection timeout: '+str(tout)+'\n')
  if(fplimit!=40 and fplimit<len(shellz)):
    settings.append('** Custom threshold for false/positive detection: '+str(fplimit)+'\n')
    settings.append('   (note that changing this value is usually not needed)\n')
  elif(fplimit!=40 and fplimit>=len(shellz)):
    settings.append('** Custom threshold for false/positive detection: '+str(fplimit)+'\n')
    settings.append('   INFO: threshold set equal or higher than number of shells ('+str(len(shellz))+'),\n')
    settings.append('   this will completely eliminate the detection of False/Positives!\n')
  if skipOn:
    settings.append('** Ignoring targets online probes (this may increase scanning time)\n')
  if(tout<1):
    settings.append('** WARNING: even with good ping you should not go < 1 sec,\n')
    settings.append('   otherwise some of the vulnerability checks could fail!\n')
  if LocalSSRF:
    settings.append('** Using local SSRF for CVE detection (same method as the nmap\n')
    settings.append('   script uses). Run -h to see alternate options (-r and -n)\n')
  elif not NSA:
    settings.append('** Switching from local to -remote- SSRF identifiers,\n')
    settings.append('   This will cause some requests to Amazon and Pornhub (but nothing harmfull)\n')
    settings.append('   With this method, we may grab a few more results that could have been missed\n')
    settings.append('   with local SSRF method (scenario seen in dev-tests with 3000+ targets).\n')
  elif NSA:
    settings.append('** Using NSA Website as remote SSRF identifier :3\n')
    settings.append('   This does not upper the detection chances vs amazon/pornhub method (-r),\n')
    settings.append('   but for the cowboys among us (not suited for scans with 1000+ targets:)\n')
  if verbose:
    settings.append('** Running in verbose mode for more detailed output\n')
  if outputfile:
    settings.append('** Output will be written to: '+outputfile+'\n')
  for line in settings:
    print(line.replace('\n',''))

def init():
  global inputfile, outputfile, stack, threadcounter, itemscount, unduped
  args()
  if(target != ''):
    items = []
    items.append(target)
    unduped.append(target)
    itemscount+=1
  else:
    passed = False
    while passed != True:
      if not inputfile:
        inputfile = input('** Select input file: ')
      try:
        fileexists = open(inputfile,'r')
        items = fileexists.read()
        fileexists.close()
        passed = True
      except:
        print('>> ERROR: input file not found or corrupted')
        inputfile=''
    if(len(items))>1:
      try:
        items = items.split('\n')
      except:
        print('>> ERROR: input corrupted!')
        print('   Make sure you have one url per line,')
        print('   no blank lines, no invalid url chars.')
        print('   Sorry we can\'t continue, exiting ...')
        sys.exit('** May the force be with you.\n\n')
    items = list(filter(None,items))
    for item in items:
      if item not in unduped: # clean duplicates ..
        unduped.append(item)
        itemscount+=1
  if(itemscount>1):
    print('** There is a total of '+str(itemscount)+' targets to process,')
    print('   added from input file: '+str(inputfile))
  else:
    print('** There is '+str(itemscount)+' target to process')
  print('** Scan date: '+str(time.strftime("%Y-%m-%d")))
  print('\n   -------------------')
  print('>> == RUNNING SCAN: ==')
  print('   -------------------\n')
  print('** NOTE: depending on the given targets, there might be no')
  print('         movement here for some minutes (but we are running!).\n')
  if(outputfile!=''):
    with open(outputfile,'w') as oof:
      oof.write('###########################################\n')
      oof.write('#                                         #\n')
      oof.write('#     \'ShellEX\' for Exchange Server       #\n')
      oof.write('#  (detects CVE-2021-26855 & infections)  #\n')
      oof.write('#         by twitter.com/haxel0rd         #\n')
      oof.write('#                                         #\n')
      oof.write('###########################################\n\n')    
      oof.write('** ABOUT:\n')
      oof.write('   ShellEX for Exchange v1.0, tested on win/linux with py3.7\n')
      oof.write('   (checks for webshell infections and if CVE-2021-26855 is patched)\n')
      oof.write('** MAY ONLY DETECT EARLIER VARIANTS - DO NOT RELY ON THIS TOOL!\n')
      oof.write('   Shellnames are from first attack waves (1st days after MS-Blogpost,\n')
      oof.write('   later variants may have different names / paths / behaviour!\n')
      oof.write('** SETTINGS:\n')
      for line in settings:
        oof.write(line)
      oof.write('** Detecting '+str(len(shellz))+' different webshells')
      oof.write('** Scan date: '+str(time.strftime("%Y-%m-%d"))+'\n')
      oof.write('** --------------\n')
      oof.write('** == RESULTS: ==\n')
      oof.write('** --------------\n\n')
  # no time to wait, we multithread this for quicker results
  for item in unduped:
    t = threading.Thread(target=xprobes,args=(item,))
    threadz.append(t)
  while True: # manual threads queue (:
    if(stack < tnum): # num of concurrent threads, either given by -x or 33 as default
      try:
        threadz[threadcounter].start()
      except:
        pass
    if(threadcounter==itemscount):
      break
  while stack > 0:
    pass # waiting for last threads to finish (before continuing)
  ttc = int(time.time()-started)
  ttc = ('{:02d}:{:02d}:{:02d}'.format(ttc // 3600, (ttc % 3600 // 60), ttc % 60))
  print('\n** DONE: all checks finished,')
  print('   Time for operations to complete: '+ttc)
  if(infections!=0):
    print('>> INFECTIONS: detected '+str(infections)+' out of '+str(itemscount)+' targets as infected!')
  else:
    print('** No infections detected in '+str(itemscount)+' targets')
  if(vulnscount!=0):
    print('>> VULNERABLE: '+str(vulnscount)+' from '+str(itemscount)+' are vulnerable to CVE-2021-26855')
  else:
    print('** No vulnerable Servers detected in '+str(itemscount)+' targets')
  if(outputfile!=''):
    with open(outputfile,'a') as oof:
      oof.write('\n** DONE: all checks finished\n')
      if(infections!=0):
        oof.write('>> INFECTIONS: detected '+str(infections)+' out of '+str(itemscount)+' targets as infected!')
      else:
        oof.write('** No infections detected in '+str(itemscount)+' targets')
        oof.write('   (this does not guarantee you\'re safe, there may be newer variants!)')
      if(vulnscount!=0):
        oof.write('>> VULNERABLE: '+str(vulnscount)+' from '+str(itemscount)+' are vulnerable to CVE-2021-26855')
      else:
        oof.write('** No vulnerable Servers detected in '+str(itemscount)+' targets')
        oof.write('   (this does not guarantee you\'re safe, checks are for shells and CVE-2021-26855!)')
      oof.write('** Time for operations to complete: '+ttc)
      oof.write('   Results written to \''+outputfile+'\' for later inspection\n')
      oof.write('** May the force be with you.\n\n\n')
    print('   Results written to \''+outputfile+'\' for later inspection')
  sys.exit('** May the force be with you.\n\n')
  
def xprobes(item):
  global threadcounter, stack, infections, vulnscount
  stack+=1
  msg = ''
  prnt=False
  infected = False
  suffix = '<error>'
  vulnerable = False
  threadcounter+=1
  host = (item,port)
  hpack = xprobe.replace('{{host}}',item)
  controlflag = '     [ ? ]'
  fpswitch = 0 # filtering out false/positives..
  isOn = ping(item)
  if isOn or skipOn:
    for shell in shellz:
      packet = hpack.replace('{{shell}}',shell)
      response = netw(host,packet)
      try:
        code = str(response.split(' ')[1])[0:3]
      except:
        code='err'
      if(shell=='../owa/auth/logon.aspx'):
        shell = 'FAILCHECK indicator'
        if(code=='200'):
            controlflag = '     [OK!]'
      if (shell[0:19]!='FAILCHECK indicator'):
        if(code=='200' or code=='500'):
          status = '  infected ('+str(code)+')'
          infected = True
          fpswitch+=1        
          if(code == '200'):
            status+='(!)'
        else:
          status = '    ---    ('+str(code)+')'
      while(len(shell))<30:
        shell+=' '
      if not verbose:
        if(code=='500' or code=='200' and shell[0:19]!='FAILCHECK indicator'):
          if(shell[0:3]=='../'):
            shell = shell.replace('..','')
            while(len(shell))<45:
              shell+=' '
          else:
            shell = '/aspnet_client/'+shell
            while(len(shell))<30:
              shell+=' '
          msg+='   -- '+shell+': '+status.split(' (')[0]+'\n'
      else:
        if(shell[0:19]!='FAILCHECK indicator'):
          if(shell[0:3]=='../'):
            shell = shell.replace('..','')
            while(len(shell))<45:
              shell+=' '
          else:
            shell = '/aspnet_client/'+shell
            while(len(shell))<30:
              shell+=' '
          msg+='   -- '+shell+': '+status+'\n'
    prnt=False
    nones=[]
    # shell checks done, now check if target is still vulnerable to CVE-2021-26855
    vulnerable = isVuln(host)
  else:
    infected = False
    vulnerable = False
    controlflag = '     [OFF]'
  msgheader='\n** Target: '+item+' {{placeholder}}\n   ---------------------------------------------------------------------\n   => FAILCHECK indicator                          :'+controlflag+'\n'
  fpindicator = False
  # catching false positives
  # if around 50% shellz report as true, we are most likely dealing with a false positive for this target
  if(fpswitch>fplimit): 
    fpindicator = True
  if vulnerable and not infected:
    prnt = True
    vulnscount+=1
    suffix = '(VULNERABLE)'
    msgheader+='   => Target is VULNERABLE to CVE-2021-26855!      :  VULNERABLE!\n'
  elif infected and not vulnerable:
    if(fpindicator==True):
      infected = False
      suffix = '(FALSE/POSITIVE)'
      controlflag = '     [F/P]'
      msg='   => Infections False/Positive on Target!         :    INVALID!\n'
      msg+='      This means the target threw more than '+str(fplimit)+'\n'
      msg+='      infection results which could be caused\n'
      msg+='      by unusual target behaviour.\n'
      msgheader=msgheader.replace('\n   => FAILCHECK indicator                          :     [ ? ]','\n   => FAILCHECK indicator                          :     [F/P]')
      msgheader=msgheader.replace('\n   => FAILCHECK indicator                          :     [OK!]','\n   => FAILCHECK indicator                          :     [F/P]')
      msgheader=msgheader.replace('\n   => FAILCHECK indicator                          :     [OFF]','\n   => FAILCHECK indicator                          :     [F/P]')
    else:
      prnt = True
      infections+=1
      infected = True
      suffix = '(INFECTED)'
      msgheader+='   => Target is INFECTED with Hafnium webshells!   :   INFECTED!\n'
  elif vulnerable and infected:
    msgheader+='   => Target is VULNERABLE to CVE-2021-26855!      :  VULNERABLE!\n'
    if(fpindicator==True):
      infected = False
      suffix = '(FALSE/POSITIVE)'
      controlflag = '     [F/P]'
      msg='   => Infections False/Positive on Target!         :    INVALID!\n'
      msg+='      This means the target threw more than '+str(fplimit)+'\n'
      msg+='      infection results which could be caused by\n'
      msg+='      unusual target behaviour.\n'
    else:
      infections+=1
      infected = True
      suffix = '(VULNERABLE, INFECTED)'
      msgheader+='   => Target is INFECTED with Hafnium webshells!   :   INFECTED!\n'
    prnt = True
    vulnscount+=1
  else:
    suffix = '(NONE)'
  if not isOn and not skipOn:
    suffix = '(OFFLINE)'
    msgheader+='   => Target offline or blocking pings, aborting   :    OFFLINE!\n'
    msgheader+='      checks. If you believe this is an error,\n'
    msgheader+='      ignore target online probes with -d option\n'
    msg=''
  if verbose:
    prnt = True
    msgheader=msgheader.replace('{{placeholder}}',suffix)
  else:
    msgheader=msgheader.replace('{{placeholder}}','')
    msgheader=msgheader.replace('\n   => FAILCHECK indicator                          :     [OK!]','') # Online, stable/normal behavior of target
    msgheader=msgheader.replace('\n   => FAILCHECK indicator                          :     [ ? ]','') # Unstable/unreliable target behavior (in rare situations these could cause false/positives, check manually if you want to go sure)
    msgheader=msgheader.replace('\n   => FAILCHECK indicator                          :     [F/P]','') # indicator that the target is offline 
    msgheader=msgheader.replace('\n   => FAILCHECK indicator                          :     [OFF]','') # indicator that the target is offline 
  msg=msgheader+msg
  if prnt:
    print(msg)
    if(outputfile!=''):
      with open(outputfile,'a') as oof:
        oof.write(msg)
  stack-=1

def isVuln(host):
  # checking for SSRF.. by exploiting it (:
  vuln = False
  payload = yprobe.replace('{{target}}',host[0])
  if(LocalSSRF==True):
    payload = payload.replace('X-AnonResource-Backend={{identifier}}/#~1;X-AnonResource=true;','X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;')
    vulnresponse = netw(host,payload)
    vuln = re.search(' 500 Internal Server Error',vulnresponse)
  else:
    if(NSA!=True):
      # for processing larger lists of targets, we use Amazon and Pornhub (fallback) 
      # as fail/success indicator for the SSRF, as they can easily handle high loads
      payload1 = payload.replace('{{identifier}}','amazon.com')
      vulnresponse1 = netw(host,payload1)
      vuln = re.search('[Ll]ocation: https://www.amazon.com/',vulnresponse1)
      if not vuln:
        payload2 = payload.replace('{{identifier}}','pornhub.com')
        vulnresponse2 = netw(host,payload2)
        vuln = re.search('[Ll]ocation: https://www.pornhub.com/',vulnresponse2)
    else:
      # for the cowboys among us...
      payload = payload.replace('{{identifier}}','nsa.gov')
      vulnresponse = netw(host,payload)
      vuln = re.search('Target: nsa.gov',vulnresponse)
      if not vuln:
        vuln = re.search('[Ll]ocation: https://www.nsa.gov/',vulnresponse)
      if not vuln:
        cpattern = re.compile('<title>.*?(National Security Agency).*?</title>', re.MULTILINE|re.DOTALL)
        vuln = re.search(cpattern,vulnresponse)
  if vuln:
    return True
  if not vuln:
    return False

def ping(target):
  # quick and dirty version of my own icmp-ping implementation
  # (replaced manual package crafting with ready made byte-seq to send to shorten the code)
  pong = None
  error = None
  with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
    sock.settimeout(3)
    resp=bytearray()
    try:
      sock.connect((target,7))
      sock.send(b'\x08\x00f\xbb\x91C\x00\x01') # ez ping lmao
      resp,addr = sock.recvfrom(4096)
    except:
      error=True
    if not error:
      try:
        respUnpack = struct.unpack("s",bytes([resp[8]]))[0]
        pong=int(hexlify(respUnpack),16) #TTL
        byte=struct.calcsize("d")
      except:
        pass
    if pong:
      return True
  # else: target did not respond to ICMP ping, send "HTTP ping" incase target is online and ICMP was just blocked
  httpPack = xprobe.replace('GET /aspnet_client/{{shell}} HTTP/1.1','GET /index.html HTTP/1.1')
  response = netw((target,port),httpPack)
  lookup = re.search('HTTP/',response)
  if lookup:
    return True
  else:
    return False

def netw(host,packet):
# networking functions based on raw sockets.. from Haxe with <3
  unfound = 1
  response = ''
  while unfound < 5:
    #print('[+] Firing request for '+str(host[0])) #dev-debugging
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
      sock.settimeout(tout)
      sock.connect(host)
      sock.send(packet.encode("utf-8"))
      i = 0;
      e = 0;
      while i < 1337: # Limited rounds to prevent getting stuck in loops when no EOF
        chunk = str(sock.recv(4096))
        response += chunk
        if re.search('charset=UTF-8',response) != None: # for HEAD requests, specific to scenario
          unfound = 5
          break
        response = response.replace('\\r\\n','').replace('\r\n','')
        if re.search('</html>',str(response)) != None:
          unfound = 5
          break
        if (chunk == "b''"):
          e+=1
          if (e > 7):
            unfound = 5
            break
        i+=1
      unfound+=1
    except socket.error as sockerr:
      break
    except socket.timeout:
      break
  return response
  
# MAIN program entry:
#--------------------
init()
#--------------------


