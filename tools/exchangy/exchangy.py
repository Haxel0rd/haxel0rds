# -*- coding: utf-8 -*-
##############################################################################
# Copyright (c) 2021 Haxel0rd                                                #
# Published under the GNU general Public Licence v3                          #
# See LICENCE File for more details:                                         #
# https://github.com/Haxel0rd/haxel0rds/tree/master/tools/exchangy           #
#                                                                            #
# BUG REPORTS:                                                               #
#   > Please send Bug reports to: twitter.com/haxel0rd                       #
#   > (i see may this faster than on github). Thank you.                     #
#                                                                            #
# ------------------------------------------------------------               #
# Exchangy - Exchange Server version & patchlevel detection                  #
# ------------------------------------------------------------               #
# - Creation: 06/2020, version: v1.0                                         #
# - Recoded:  02/2021, version: v1.1                                         #
# - Requires OWA to run at target (fetching build number from there)         #
# - Runs on: Win, Linux / py3 (tested: 3.7.0 native, no additional libs)     #
# - Supports: Exchange 20XX down to Exchange prior 2000, SSL/TLS any version #
# - Works: Remote / unauthenticated / BlackBox point of view                 #
# - Supported Patchlevels are:                                               #
#   ServicePack (SP), CumulativeUpdates (CU) and RollupUpdates (RU).         #
#   (single KB patches can then be looked up with this information)          #
# - Can even deal even with customized and "cleansed" owa panels             #
# - Bypasses some things, except F5 Bot-Protection and layer-3 firewalls     #
# - As of OpenSSL v1.0.1r and 1.0.2f, we cant probe targets with weak        #
#   SSL/TLS Ciphers anymore, this is not in the hands of this tool!          #
#   More info on this: https://stackoverflow.com/a/56587377 and from         #
#   OpenSSL changelog: https://www.openssl.org/news/changelog.html           #
#   (search for "weak-ciphers")                                              #
# - May the force be with you.                                               #
#                                                                            #
##############################################################################


# it looked tidier without try catches, but we want to catch as many errors as possible
try:
  import sys
except:
  print('\n>> ERROR: dependency missing: sys')
  print('   Get this at https://pypi.org/ or install fresh python 3.7')
  print('   Sorry we can\'t continue, exiting ...')
  print('** May the force be with you.\n\n')
  import os
  os._exit(0) # if this is not available, then we're unlucky
try:
  import re
except:
  print('\n>> ERROR: dependency missing: re')
  print('   Get this at https://pypi.org/ or install a fresh python 3.7')
  print('   Sorry we can\'t continue, exiting ...')
  sys.exit('** May the force be with you.\n\n')
try:
  import ssl
except:
  print('\n>> ERROR: dependency missing: ssl')
  print('   Get this at https://pypi.org/ or install a fresh python 3.7')
  print('   Sorry we can\'t continue, exiting ...')
  sys.exit('** May the force be with you.\n\n')
try:
  import uuid
except:
  print('\n>> ERROR: dependency missing: uuid')
  print('   Get this at https://pypi.org/ or install a fresh python 3.7')
  print('   Sorry we can\'t continue, exiting ...')
  sys.exit('** May the force be with you.\n\n')
try:
  import json
except:
  print('\n>> ERROR: dependency missing: json')
  print('   Get this at https://pypi.org/ or install a fresh python 3.7')
  print('   Sorry we can\'t continue, exiting ...')
  sys.exit('** May the force be with you.\n\n')
try:
  import getopt
except:
  print('\n>> ERROR: dependency missing: getopt')
  print('   Get this at https://pypi.org/ or install a fresh python 3.7')
  print('   Sorry we can\'t continue, exiting ...')
  sys.exit('** May the force be with you.\n\n')
try:
  import socket
except:
  print('\n>> ERROR: dependency missing: socket')
  print('   Get this at https://pypi.org/ or install a fresh python 3.7')
  print('   Sorry we can\'t continue, exiting ...')
  sys.exit('** May the force be with you.\n\n')


# Versioning Database:
db = '{"toolinfo":{"tool_name":"Exchangy","tool_desc":"Exchange Server and Patchlevel detection (BlackBox, remote, unauthenticated)","tool_version_latest":"v1.01","db_version":"v00001","author-contact":"twitter.com/haxel0rd","author-github":"https://github.com/Haxel0rd/haxel0rds/"},"0":{"name":"<unknown>","release":"<unknown>","date":"<unknown>","buildno_s":"<unknown>","buildno_l":"<unknown>"},"1":{"name":"Exchange Server 4.0","release":"/","date":"11.06.1996","buildno_s":"4.0.837","buildno_l":"/"},"2":{"name":"Exchange Server 4.0","release":"SP1","date":"1.05.1996","buildno_s":"4.0.838","buildno_l":"/"},"3":{"name":"Exchange Server 4.0","release":"SP2","date":"19.07.1996","buildno_s":"4.0.993","buildno_l":"/"},"4":{"name":"Exchange Server 4.0","release":"SP3","date":"29.10.1996","buildno_s":"4.0.994","buildno_l":"/"},"5":{"name":"Exchange Server 4.0","release":"SP4","date":"28.03.1997","buildno_s":"4.0.995","buildno_l":"/"},"6":{"name":"Exchange Server 4.0","release":"SP5","date":"5.05.1998","buildno_s":"4.0.996","buildno_l":"/"},"7":{"name":"Exchange Server 5.0","release":"/","date":"23.05.1997","buildno_s":"5.0.1457","buildno_l":"/"},"8":{"name":"Exchange Server 5.0","release":"SP1","date":"18.06.1997","buildno_s":"5.0.1458","buildno_l":"/"},"9":{"name":"Exchange Server 5.0","release":"SP2","date":"19.02.1998","buildno_s":"5.0.1460","buildno_l":"/"},"10":{"name":"Exchange Server 5.5","release":"/","date":"03.02.1998","buildno_s":"5.5.1960","buildno_l":"/"},"11":{"name":"Exchange Server 5.5","release":"SP1","date":"05.08.1998","buildno_s":"5.5.2232","buildno_l":"/"},"12":{"name":"Exchange Server 5.5","release":"SP2","date":"23.12.1998","buildno_s":"5.5.2448","buildno_l":"/"},"13":{"name":"Exchange Server 5.5","release":"SP3","date":"09.09.1999","buildno_s":"5.5.2650","buildno_l":"/"},"14":{"name":"Exchange Server 5.5","release":"SP4","date":"01.11.2000","buildno_s":"5.5.2653","buildno_l":"/"},"15":{"name":"Exchange Server 2000","release":"/","date":"29.11.2000","buildno_s":"6.0.4417","buildno_l":"/"},"16":{"name":"Exchange Server 2000","release":"SP1","date":"21.06.2001","buildno_s":"6.0.4712","buildno_l":"/"},"17":{"name":"Exchange Server 2000","release":"SP2","date":"29.11.2001","buildno_s":"6.0.5762","buildno_l":"/"},"18":{"name":"Exchange Server 2000","release":"SP3","date":"18.07.2002","buildno_s":"6.0.6249","buildno_l":"/"},"19":{"name":"Exchange Server 2000","release":"SP3 (post)","date":"01.09.2003","buildno_s":"6.0.6487","buildno_l":"/"},"20":{"name":"Exchange Server 2000","release":"SP3 (post)","date":"01.04.2004","buildno_s":"6.0.6556","buildno_l":"/"},"21":{"name":"Exchange Server 2000","release":"SP3 (post)","date":"01.08.2004","buildno_s":"6.0.6603","buildno_l":"/"},"22":{"name":"Exchange Server 2000","release":"SP3 (post)","date":"01.03.2008","buildno_s":"6.0.6620.5","buildno_l":"/"},"23":{"name":"Exchange Server 2000","release":"SP3 (post)","date":"01.08.2008","buildno_s":"6.0.6620.7","buildno_l":"/"},"24":{"name":"Exchange Server 2003","release":"/","date":"28.09.2003","buildno_s":"6.5.6944","buildno_l":"/"},"25":{"name":"Exchange Server 2003","release":"SP1","date":"25.05.2004","buildno_s":"6.5.7226","buildno_l":"/"},"26":{"name":"Exchange Server 2003","release":"SP2","date":"19.10.2005","buildno_s":"6.5.7683","buildno_l":"/"},"27":{"name":"Exchange Server 2003","release":"SP2 (post)","date":"01.03.2008","buildno_s":"6.5.7653.33","buildno_l":"/"},"28":{"name":"Exchange Server 2003","release":"SP2 (post)","date":"01.03.2008","buildno_s":"6.5.7654.4","buildno_l":"/"},"29":{"name":"Exchange Server 2007","release":"RTM","date":"08.03.2007","buildno_s":"8.0.685.25","buildno_l":"8.00.0685.025"},"30":{"name":"Exchange Server 2007","release":"Update Rollup 1","date":"17.04.2007","buildno_s":"8.0.708.3","buildno_l":"8.00.0708.003"},"31":{"name":"Exchange Server 2007","release":"Update Rollup 2","date":"08.05.2007","buildno_s":"8.0.711.2","buildno_l":"8.00.0711.002"},"32":{"name":"Exchange Server 2007","release":"Update Rollup 3","date":"28.06.2007","buildno_s":"8.0.730.1","buildno_l":"8.00.0730.001"},"33":{"name":"Exchange Server 2007","release":"Update Rollup 4","date":"23.08.2007","buildno_s":"8.0.744.0","buildno_l":"8.00.0744.000"},"34":{"name":"Exchange Server 2007","release":"Update Rollup 5","date":"25.10.2007","buildno_s":"8.0.754.0","buildno_l":"8.00.0754.000"},"35":{"name":"Exchange Server 2007","release":"Update Rollup 6","date":"21.02.2008","buildno_s":"8.0.783.2","buildno_l":"8.00.0783.002"},"36":{"name":"Exchange Server 2007","release":"Update Rollup 7","date":"08.07.2008","buildno_s":"8.0.813.0","buildno_l":"8.00.0813.000"},"37":{"name":"Exchange Server 2007","release":"SP1","date":"29.11.2007","buildno_s":"8.1.240.6","buildno_l":"8.01.0240.006"},"38":{"name":"Exchange Server 2007","release":"SP1, Update Rollup 1","date":"28.02.2008","buildno_s":"8.1.263.1","buildno_l":"8.01.0263.001"},"39":{"name":"Exchange Server 2007","release":"SP1, Update Rollup 2","date":"09.05.2008","buildno_s":"8.1.278.2","buildno_l":"8.01.0278.002"},"40":{"name":"Exchange Server 2007","release":"SP1, Update Rollup 3","date":"08.07.2008","buildno_s":"8.1.291.2","buildno_l":"8.01.0291.002"},"41":{"name":"Exchange Server 2007","release":"SP1, Update Rollup 4","date":"07.09.2008","buildno_s":"8.1.311.3","buildno_l":"8.01.0311.003"},"42":{"name":"Exchange Server 2007","release":"SP1, Update Rollup 5","date":"20.11.2008","buildno_s":"8.1.336.1","buildno_l":"8.01.0336.01"},"43":{"name":"Exchange Server 2007","release":"SP1, Update Rollup 6","date":"10.02.2009","buildno_s":"8.1.340.1","buildno_l":"8.01.0340.001"},"44":{"name":"Exchange Server 2007","release":"SP1, Update Rollup 7","date":"18.03.2009","buildno_s":"8.1.359.2","buildno_l":"8.01.0359.002"},"45":{"name":"Exchange Server 2007","release":"SP1, Update Rollup 8","date":"19.05.2009","buildno_s":"8.1.375.2","buildno_l":"8.01.0375.002"},"46":{"name":"Exchange Server 2007","release":"SP1, Update Rollup 9","date":"16.07.2009","buildno_s":"8.1.393.1","buildno_l":"8.01.0393.001"},"47":{"name":"Exchange Server 2007","release":"SP1, Update Rollup 10","date":"13.04.2010","buildno_s":"8.1.436.0","buildno_l":"8.01.0436.000"},"48":{"name":"Exchange Server 2007","release":"SP2","date":"24.08.2009","buildno_s":"8.2.176.2","buildno_l":"8.02.0176.002"},"49":{"name":"Exchange Server 2007","release":"SP2, Update Rollup 1","date":"19.11.2009","buildno_s":"8.2.217.3","buildno_l":"8.02.0217.003"},"50":{"name":"Exchange Server 2007","release":"SP2, Update Rollup 2","date":"22.01.2010","buildno_s":"8.2.234.1","buildno_l":"8.02.0234.001"},"51":{"name":"Exchange Server 2007","release":"SP2, Update Rollup 3","date":"17.03.2010","buildno_s":"8.2.247.2","buildno_l":"8.02.0247.002"},"52":{"name":"Exchange Server 2007","release":"SP2, Update Rollup 4","date":"09.04.2010","buildno_s":"8.2.254.0","buildno_l":"8.02.0254.000"},"53":{"name":"Exchange Server 2007","release":"SP2, Update Rollup 5","date":"07.12.2010","buildno_s":"8.2.305.3","buildno_l":"8.02.0305.003"},"54":{"name":"Exchange Server 2007","release":"SP3","date":"07.06.2010","buildno_s":"8.3.83.6","buildno_l":"8.03.0083.006"},"55":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 1","date":"09.09.2010","buildno_s":"8.3.106.2","buildno_l":"8.03.0106.002"},"56":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 2","date":"10.12.2010","buildno_s":"8.3.137.3","buildno_l":"8.03.0137.003"},"57":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 3-v2","date":"30.03.2011","buildno_s":"8.3.159.2","buildno_l":"8.03.0159.002"},"58":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 4","date":"28.05.2011","buildno_s":"8.3.192.1","buildno_l":"8.03.0192.001"},"59":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 5","date":"21.09.2011","buildno_s":"8.3.213.1","buildno_l":"8.03.0213.001"},"60":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 6","date":"26.01.2012","buildno_s":"8.3.245.2","buildno_l":"8.03.0245.002"},"61":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 7","date":"16.04.2012","buildno_s":"8.3.264.0","buildno_l":"8.03.0264.000"},"62":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 8","date":"13.08.2012","buildno_s":"8.3.279.3","buildno_l":"8.03.0279.003"},"63":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 8-v2","date":"09.10.2012","buildno_s":"8.3.279.5","buildno_l":"8.03.0279.005"},"64":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 8-v3","date":"13.11.2012","buildno_s":"8.3.279.6","buildno_l":"8.03.0279.006"},"65":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 9","date":"10.12.2012","buildno_s":"8.3.297.2","buildno_l":"8.03.0297.002"},"66":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 10","date":"11.02.2013","buildno_s":"8.3.298.3","buildno_l":"8.03.0298.003"},"67":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 11","date":"13.08.2013","buildno_s":"8.3.327.1","buildno_l":"8.03.0327.001"},"68":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 12","date":"09.12.2013","buildno_s":"8.3.342.4","buildno_l":"8.03.0342.004"},"69":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 13","date":"24.02.2014","buildno_s":"8.3.348.2","buildno_l":"8.03.0348.002"},"70":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 14","date":"26.08.2014","buildno_s":"8.3.379.2","buildno_l":"8.03.0379.002"},"71":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 15","date":"09.12.2014","buildno_s":"8.3.389.2","buildno_l":"8.03.0389.002"},"72":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 16","date":"17.03.2015","buildno_s":"8.3.406.0","buildno_l":"8.03.0406.000"},"73":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 17","date":"17.06.2015","buildno_s":"8.3.417.1","buildno_l":"8.03.0417.001"},"74":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 18","date":"December.12.2015","buildno_s":"8.3.445.0","buildno_l":"8.03.0445.000"},"75":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 19","date":"15.03.2016","buildno_s":"8.3.459.0","buildno_l":"8.03.0459.000"},"76":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 20","date":"21.06.2016","buildno_s":"8.3.468.0","buildno_l":"8.03.0468.000"},"77":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 21","date":"20.09.2016","buildno_s":"8.3.485.1","buildno_l":"8.03.0485.001"},"78":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 22","date":"13.12.2016","buildno_s":"8.3.502.0","buildno_l":"8.03.0502.000"},"79":{"name":"Exchange Server 2007","release":"SP3, Update Rollup 23","date":"21.03.2017","buildno_s":"8.3.517.0","buildno_l":"8.03.0517.000"},"80":{"name":"Exchange Server 2010","release":"RTM","date":"09.11.2009","buildno_s":"14.0.639.21","buildno_l":"14.00.0639.021"},"81":{"name":"Exchange Server 2010","release":"Update Rollup 1","date":"09.12.2009","buildno_s":"14.0.682.1","buildno_l":"14.00.0682.001"},"82":{"name":"Exchange Server 2010","release":"Update Rollup 2","date":"04.03.2010","buildno_s":"14.0.689.0","buildno_l":"14.00.0689.000"},"83":{"name":"Exchange Server 2010","release":"Update Rollup 3","date":"13.04.2010","buildno_s":"14.0.694.0","buildno_l":"14.00.0694.000"},"84":{"name":"Exchange Server 2010","release":"Update Rollup 4","date":"10.06.2010","buildno_s":"14.0.702.1","buildno_l":"14.00.0702.001"},"85":{"name":"Exchange Server 2010","release":"Update Rollup 5","date":"13.12.2010","buildno_s":"14.0.726.0","buildno_l":"14.00.0726.000"},"86":{"name":"Exchange Server 2010","release":"SP1","date":"23.08.2010","buildno_s":"14.1.218.15","buildno_l":"14.01.0218.015"},"87":{"name":"Exchange Server 2010","release":"SP1, Update Rollup 1","date":"04.10.2010","buildno_s":"14.1.255.2","buildno_l":"14.01.0255.002"},"88":{"name":"Exchange Server 2010","release":"SP1, Update Rollup 2","date":"09.12.2010","buildno_s":"14.1.270.1","buildno_l":"14.01.0270.001"},"89":{"name":"Exchange Server 2010","release":"SP1, Update Rollup 3","date":"06.04.2011","buildno_s":"14.1.289.7","buildno_l":"14.01.0289.007"},"90":{"name":"Exchange Server 2010","release":"SP1, Update Rollup 4","date":"27.07.2011","buildno_s":"14.1.323.6","buildno_l":"14.01.0323.006"},"91":{"name":"Exchange Server 2010","release":"SP1, Update Rollup 5","date":"23.08.2011","buildno_s":"14.1.339.1","buildno_l":"14.01.0339.001"},"92":{"name":"Exchange Server 2010","release":"SP1, Update Rollup 6","date":"27.10.2011","buildno_s":"14.1.355.2","buildno_l":"14.01.0355.002"},"93":{"name":"Exchange Server 2010","release":"SP1, Update Rollup 7","date":"08.08.2012","buildno_s":"14.1.421.0","buildno_l":"14.01.0421.000"},"94":{"name":"Exchange Server 2010","release":"SP1, Update Rollup 7 v2","date":"10.10.2012","buildno_s":"14.1.421.2","buildno_l":"14.01.0421.002"},"95":{"name":"Exchange Server 2010","release":"SP1, Update Rollup 7 v3","date":"13.11.2012","buildno_s":"14.1.421.3","buildno_l":"14.01.0421.003"},"96":{"name":"Exchange Server 2010","release":"SP1, Update Rollup 8","date":"10.12.2012","buildno_s":"14.1.438.0","buildno_l":"14.01.0438.000"},"97":{"name":"Exchange Server 2010","release":"SP2","date":"04.12.2011","buildno_s":"14.2.247.5","buildno_l":"14.02.0247.005"},"98":{"name":"Exchange Server 2010","release":"SP2, Update Rollup 1","date":"13.02.2012","buildno_s":"14.2.283.3","buildno_l":"14.02.0283.003"},"99":{"name":"Exchange Server 2010","release":"SP2, Update Rollup 2","date":"16.04.2012","buildno_s":"14.2.298.4","buildno_l":"14.02.0298.004"},"100":{"name":"Exchange Server 2010","release":"SP2, Update Rollup 3","date":"29.05.2012","buildno_s":"14.2.309.2","buildno_l":"14.02.0309.002"},"101":{"name":"Exchange Server 2010","release":"SP2, Update Rollup 4","date":"13.08.2012","buildno_s":"14.2.318.2","buildno_l":"14.02.0318.002"},"102":{"name":"Exchange Server 2010","release":"SP2, Update Rollup 4 v2","date":"09.10.2012","buildno_s":"14.2.318.4","buildno_l":"14.02.0318.004"},"103":{"name":"Exchange Server 2010","release":"SP2, Update Rollup 5","date":"13.11.2012","buildno_s":"14.3.328.5","buildno_l":"14.03.0328.005"},"104":{"name":"Exchange Server 2010","release":"SP2, Update Rollup 5 v2","date":"10.12.2012","buildno_s":"14.2.328.10","buildno_l":"14.02.0328.010"},"105":{"name":"Exchange Server 2010","release":"SP2, Update Rollup 6","date":"12.02.2013","buildno_s":"14.2.342.3","buildno_l":"14.02.0342.003"},"106":{"name":"Exchange Server 2010","release":"SP2, Update Rollup 7","date":"03.08.2013","buildno_s":"14.2.375.0","buildno_l":"14.02.0375.000"},"107":{"name":"Exchange Server 2010","release":"SP2, Update Rollup 8","date":"09.12.2013","buildno_s":"14.2.390.3","buildno_l":"14.02.0390.003"},"108":{"name":"Exchange Server 2010","release":"SP3","date":"12.02.2013","buildno_s":"14.3.123.4","buildno_l":"14.03.0123.004"},"109":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 1","date":"29.05.2013","buildno_s":"14.3.146.0","buildno_l":"14.03.0146.000"},"110":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 2","date":"08.08.2013","buildno_s":"14.3.158.1","buildno_l":"14.03.0158.001"},"111":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 3","date":"25.11.2013","buildno_s":"14.3.169.1","buildno_l":"14.03.0169.001"},"112":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 4","date":"09.12.2013","buildno_s":"14.3.174.1","buildno_l":"14.03.0174.001"},"113":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 5","date":"24.02.2014","buildno_s":"14.3.181.6","buildno_l":"14.03.0181.006"},"114":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 6","date":"27.05.2014","buildno_s":"14.3.195.1","buildno_l":"14.03.0195.001"},"115":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 7","date":"26.08.2014","buildno_s":"14.3.210.2","buildno_l":"14.03.0210.002"},"116":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 8 v1 (recalled)","date":"09.12.2014","buildno_s":"14.3.224.1","buildno_l":"14.03.0224.001"},"117":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 8 v2","date":"12.12.2014","buildno_s":"14.3.224.2","buildno_l":"14.03.0224.002"},"118":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 9","date":"17.03.2015","buildno_s":"14.3.235.1","buildno_l":"14.03.0235.001"},"119":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 10","date":"17.06.2015","buildno_s":"14.3.248.2","buildno_l":"14.03.0248.002"},"120":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 11","date":"15.09.2015","buildno_s":"14.3.266.2","buildno_l":"14.03.0266.002"},"121":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 12","date":"15.12.2015","buildno_s":"14.3.279.2","buildno_l":"14.03.0279.002"},"122":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 13","date":"15.03.2016","buildno_s":"14.3.294.0","buildno_l":"14.03.0294.000"},"123":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 14","date":"21.06.2016","buildno_s":"14.3.301.0","buildno_l":"14.03.0301.000"},"124":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 15","date":"20.09.2016","buildno_s":"14.3.319.2","buildno_l":"14.03.0319.002"},"125":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 16","date":"13.12.2016","buildno_s":"14.3.336.0","buildno_l":"14.03.0336.000"},"126":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 17","date":"21.03.2017","buildno_s":"14.3.352.0","buildno_l":"14.03.0352.000"},"127":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 18","date":"11.07.2017","buildno_s":"14.3.361.1","buildno_l":"14.03.0361.001"},"128":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 19","date":"19.12.2017","buildno_s":"14.3.382.0","buildno_l":"14.03.0382.000"},"129":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 20","date":"05.03.2018","buildno_s":"14.3.389.1","buildno_l":"14.03.0389.001"},"130":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 21","date":"07.05.2018","buildno_s":"14.3.399.2","buildno_l":"14.03.0399.002"},"131":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 22","date":"19.06.2018","buildno_s":"14.3.411.0","buildno_l":"14.03.0411.000"},"132":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 23","date":"13.08.2018","buildno_s":"14.3.417.1","buildno_l":"14.03.0417.001"},"133":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 24","date":"05.09.2018","buildno_s":"14.3.419.0","buildno_l":"14.03.0419.000"},"134":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 25","date":"08.01.2019","buildno_s":"14.3.435.0","buildno_l":"14.03.0435.000"},"135":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 26","date":"12.02.2019","buildno_s":"14.3.442.0","buildno_l":"14.03.0442.000"},"136":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 27","date":"09.04.2019","buildno_s":"14.3.452.0","buildno_l":"14.03.0452.000"},"137":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 28","date":"07.06.2019","buildno_s":"14.3.461.1","buildno_l":"14.03.0461.001"},"138":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 29","date":"09.07.2019","buildno_s":"14.3.468.0","buildno_l":"14.03.0468.000"},"139":{"name":"Exchange Server 2010","release":"SP3, Update Rollup 30","date":"11.02.2020","buildno_s":"14.3.496.0","buildno_l":"14.03.0496.000"},"140":{"name":"Exchange Server 2013","release":"RTM","date":"03.12.2012","buildno_s":"15.0.516.32","buildno_l":"15.00.0516.032"},"141":{"name":"Exchange Server 2013","release":"CU1","date":"02.04.2013","buildno_s":"15.0.620.29","buildno_l":"15.00.0620.029"},"142":{"name":"Exchange Server 2013","release":"CU2","date":"09.07.2013","buildno_s":"15.0.712.24","buildno_l":"15.00.0712.024"},"143":{"name":"Exchange Server 2013","release":"CU3","date":"25.11.2013","buildno_s":"15.0.775.38","buildno_l":"15.00.0775.038"},"144":{"name":"Exchange Server 2013","release":"CU4 (SP1)","date":"25.02.2014","buildno_s":"15.0.847.32","buildno_l":"15.00.0847.032"},"145":{"name":"Exchange Server 2013","release":"CU5","date":"27.05.2014","buildno_s":"15.0.913.22","buildno_l":"15.00.0913.022"},"146":{"name":"Exchange Server 2013","release":"CU6","date":"26.08.2014","buildno_s":"15.0.995.29","buildno_l":"15.00.0995.029"},"147":{"name":"Exchange Server 2013","release":"CU7","date":"9.12.2014","buildno_s":"15.0.1044.25","buildno_l":"15.00.1044.025"},"148":{"name":"Exchange Server 2013","release":"CU8","date":"17.03.2015","buildno_s":"15.0.1076.9","buildno_l":"15.00.1076.009"},"149":{"name":"Exchange Server 2013","release":"CU9","date":"17.06.2015","buildno_s":"15.0.1104.5","buildno_l":"15.00.1104.005"},"150":{"name":"Exchange Server 2013","release":"CU10","date":"15.09.2015","buildno_s":"15.0.1130.7","buildno_l":"15.00.1130.007"},"151":{"name":"Exchange Server 2013","release":"CU11","date":"15.12.2015","buildno_s":"15.0.1156.6","buildno_l":"15.00.1156.006"},"152":{"name":"Exchange Server 2013","release":"CU12","date":"15.03.2016","buildno_s":"15.0.1178.4","buildno_l":"15.00.1178.004"},"153":{"name":"Exchange Server 2013","release":"CU13","date":"21.06.2016","buildno_s":"15.0.1210.3","buildno_l":"15.00.1210.003"},"154":{"name":"Exchange Server 2013","release":"CU14","date":"20.09.2016","buildno_s":"15.0.1236.3","buildno_l":"15.00.1236.003"},"155":{"name":"Exchange Server 2013","release":"CU15","date":"13.12.2016","buildno_s":"15.0.1263.5","buildno_l":"15.00.1263.005"},"156":{"name":"Exchange Server 2013","release":"CU16","date":"21.03.2017","buildno_s":"15.0.1293.2","buildno_l":"15.00.1293.002"},"157":{"name":"Exchange Server 2013","release":"CU17","date":"27.06.2017","buildno_s":"15.0.1320.4","buildno_l":"15.00.1320.004"},"158":{"name":"Exchange Server 2013","release":"CU18","date":"19.09.2017","buildno_s":"15.0.1347.2","buildno_l":"15.00.1347.002"},"159":{"name":"Exchange Server 2013","release":"CU19","date":"19.12.2017","buildno_s":"15.0.1365.1","buildno_l":"15.00.1365.001"},"160":{"name":"Exchange Server 2013","release":"CU20","date":"20.03.2018","buildno_s":"15.0.1367.3","buildno_l":"15.00.1367.003"},"161":{"name":"Exchange Server 2013","release":"CU21","date":"19.06.2018","buildno_s":"15.0.1395.4","buildno_l":"15.00.1395.004"},"162":{"name":"Exchange Server 2013","release":"CU22","date":"12.02.2019","buildno_s":"15.0.1473.3","buildno_l":"15.00.1473.003"},"163":{"name":"Exchange Server 2013","release":"CU23","date":"18.06.2019","buildno_s":"15.0.1497.2","buildno_l":"15.00.1497.002"},"164":{"name":"Exchange Server 2016","release":"Preview","date":"22.07.2015","buildno_s":"15.1.225.16","buildno_l":"15.01.0225.016"},"165":{"name":"Exchange Server 2016","release":"RTM","date":"01.10.2015","buildno_s":"15.1.225.42","buildno_l":"15.01.0225.042"},"166":{"name":"Exchange Server 2016","release":"CU1","date":"15.03.2016","buildno_s":"15.1.396.30","buildno_l":"15.01.0396.030"},"167":{"name":"Exchange Server 2016","release":"CU2","date":"21.06.2016","buildno_s":"15.1.466.34","buildno_l":"15.01.0466.034"},"168":{"name":"Exchange Server 2016","release":"CU3","date":"20.09.2016","buildno_s":"15.1.544.27","buildno_l":"15.01.0544.027"},"169":{"name":"Exchange Server 2016","release":"CU4","date":"13.12.2016","buildno_s":"15.1.669.32","buildno_l":"15.01.0669.032"},"170":{"name":"Exchange Server 2016","release":"CU5","date":"21.03.2017","buildno_s":"15.1.845.34","buildno_l":"15.01.0845.034"},"171":{"name":"Exchange Server 2016","release":"CU6","date":"27.06.2017","buildno_s":"15.1.1034.26","buildno_l":"15.01.1034.026"},"172":{"name":"Exchange Server 2016","release":"CU7","date":"19.09.2017","buildno_s":"15.1.1261.35","buildno_l":"15.01.1261.035"},"173":{"name":"Exchange Server 2016","release":"CU8","date":"19.12.2017","buildno_s":"15.1.1415.2","buildno_l":"15.01.1415.002"},"174":{"name":"Exchange Server 2016","release":"CU9","date":"20.03.2018","buildno_s":"15.1.1466.3","buildno_l":"15.01.1466.003"},"175":{"name":"Exchange Server 2016","release":"CU10","date":"19.06.2018","buildno_s":"15.1.1531.3","buildno_l":"15.01.1531.003"},"176":{"name":"Exchange Server 2016","release":"CU11","date":"16.10.2018","buildno_s":"15.1.1591.10","buildno_l":"15.01.1591.010"},"177":{"name":"Exchange Server 2016","release":"CU12","date":"12.02.2019","buildno_s":"15.1.1713.5","buildno_l":"15.01.1713.005"},"178":{"name":"Exchange Server 2016","release":"CU13","date":"18.06.2019","buildno_s":"15.1.1779.2","buildno_l":"15.01.1779.002"},"179":{"name":"Exchange Server 2016","release":"CU14","date":"17.09.2019","buildno_s":"15.1.1847.3","buildno_l":"15.01.1847.003"},"180":{"name":"Exchange Server 2016","release":"CU15","date":"17.12.2019","buildno_s":"15.1.1913.5","buildno_l":"15.01.1913.005"},"181":{"name":"Exchange Server 2016","release":"CU16","date":"17.03.2020","buildno_s":"15.1.1979.3","buildno_l":"15.01.1979.003"},"182":{"name":"Exchange Server 2016","release":"CU17","date":"16.06.2020","buildno_s":"15.1.2044.4","buildno_l":"15.01.2044.004"},"183":{"name":"Exchange Server 2016","release":"CU18","date":"15.09.2020","buildno_s":"15.1.2106.2","buildno_l":"15.01.2106.002"},"184":{"name":"Exchange Server 2016","release":"CU19","date":"15.12.2020","buildno_s":"15.1.2176.2","buildno_l":"15.01.2176.002"},"185":{"name":"Exchange Server 2019","release":"Preview","date":"24.07.2018","buildno_s":"15.2.196.0","buildno_l":"15.02.0196.000"},"186":{"name":"Exchange Server 2019","release":"RTM","date":"22.10.2018","buildno_s":"15.2.221.12","buildno_l":"15.02.0221.012"},"187":{"name":"Exchange Server 2019","release":"CU1","date":"12.02.2019","buildno_s":"15.2.330.5","buildno_l":"15.02.0330.005"},"188":{"name":"Exchange Server 2019","release":"CU2","date":"18.06.2019","buildno_s":"15.2.397.3","buildno_l":"15.02.0397.003"},"189":{"name":"Exchange Server 2019","release":"CU3","date":"17.09.2019","buildno_s":"15.2.464.5","buildno_l":"15.02.0464.005"},"190":{"name":"Exchange Server 2019","release":"CU4","date":"17.12.2019","buildno_s":"15.2.529.5","buildno_l":"15.02.0529.005"},"191":{"name":"Exchange Server 2019","release":"CU5","date":"17.03.2020","buildno_s":"15.2.595.3","buildno_l":"15.02.0595.003"},"192":{"name":"Exchange Server 2019","release":"CU6","date":"16.06.2020","buildno_s":"15.2.659.4","buildno_l":"15.02.0659.004"},"193":{"name":"Exchange Server 2019","release":"CU7","date":"15.09.2020","buildno_s":"15.2.721.2","buildno_l":"15.02.0721.002"},"194":{"name":"Exchange Server 2019","release":"CU8","date":"15.12.2020","buildno_s":"15.2.792.3","buildno_l":"15.02.0792.003"}}'


# --- Packetz --- #
owa_packet = 'GET /owa/auth/logon.aspx HTTP/1.1\r\nHost: {{target}}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: identity\r\nUpgrade-Insecure-Requests: 1\r\nConnection: close\r\nDNT: 1\r\n\r\n'
onc_packet = 'GET / HTTP/1.1\r\nHost: {{target}}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: identity\r\nUpgrade-Insecure-Requests: 1\r\nConnection: close\r\nDNT: 1\r\n\r\n'
upd_packet = 'GET /Haxel0rd/updaters/main/exchangy/exchangy-db-updates.json?{{rndint}} HTTP/1.1\r\nHost: raw.githubusercontent.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: identity\r\nIf-None-Match: W/"{{rndint}}"\r\nConnection: close\r\nDNT: 1\r\n\r\n'
# --- Packetz --- #


# Global vars
xch = ''
owa = ''
rls = ''
plv = ''
host = ''
port = 443
target = ''
enterMode = False
office365 = False
skipOnline = False
owaConfirmed = False
xchConfirmed = False
ExchangyVersion = 'v1.01' # REMINDER: 
# CHANGE THIS WHEN RELEASING NEW VERSIONS OF THIS TOOL!
# ALSO UPDATE: tool internal DB, BANNER and the printout of HELP text
# [at all 3 places, the version number must be changed to the new one!]


def banner():
# show program banner and information
  print('\n\n####################################################')
  print('#                                                  #')
  print('#     ____            __                           #')
  print('#    / __/__ __ ____ / /  ___ _ ___  ___ _ __ __   #')
  print('#   / _/  \ \ // __// _ \/ _ `// _ \/ _ `// // /   #')
  print('#  /___/ /_\_\ \__//_//_/\_,_//_//_/\_, / \_, /    #')
  print('#                            v1.01 /___/ /___/     #')
  print('#                                                  #')
  print('#  Exchange Server version & patchlevel detection  #')
  print('#    Coded by Haxel0rd - (twitter.com/haxel0rd)    #')
  print('#                                                  #')
  print('####################################################\n\n')


banner()
# Check if python 3 is used, if not then exit
if sys.version_info[0] < 3:
  print('>> ERROR: must be run with python3 (3.7 was tested)')
  print('   Sorry we can\'t continue, exiting ...')
  sys.exit('** May the force be with you.\n\n')


def args():
# define option args
  opthalp = 0
  opttrgt = ''
  optport = ''
  optskip = 0
  optupdt = 0
  optentr = 0
  optmode = 0
  try:
    opts,args = getopt.getopt(sys.argv[1:],'ht:p:sue')
  except:
    print('>> ERROR: something went wrong with the options provided')
    print('   Sorry we can\'t continue, exiting ...')
    sys.exit('** May the force be with you.\n\n')
  for opt, arg in opts:
    if opt in ('-h'):
      opthalp = 1
    if opt in ('-t'):
      opttrgt = arg
    if opt in ('-p'):
      optport = arg
    if opt in ('-s'):
      optskip = 1
    if opt in ('-u'):
      optupdt = 1
    if opt in ('-e'):
      optentr = 1
  return opthalp, opttrgt, optport, optskip, optupdt, optentr


def update(msdb):
  global db, upd_packet, update
  err = ''
  skippy = False # if needed, abort the remaining update sequence once an error occurs
  rndint = uuid.uuid4().hex # bypassing Cache
  upd_packet = upd_packet.replace('{{rndint}}',rndint)
  git = ('raw.githubusercontent.com',443)
  https = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock = ssl.wrap_socket(https, ssl_version=ssl.PROTOCOL_TLSv1_2)
  sock.settimeout(7)
  try:
    sock.connect(git)
    sock.send(upd_packet.encode('UTF-8'))
  except:
    err = '>> ERROR: problem fetching update from server'
    skippy = True
  gitsaid = ''
  update = ''
  i = 0
  while i < 7777: # emergency exit incase we dont receive expected end of packet
    try:
      gitsays = sock.recv(4096)
    except:
      err = '>> ERROR: problem receiving the update package'
    gitsaid+= str(gitsays,'UTF-8')
    i+=1
    if (re.search('[0-9]"}}',gitsaid) != None):
      try:
        update = str(gitsaid.split('\n{"toolinfo":{"tool_name":"Exchangy",')[1])
        update = '{"toolinfo":{"tool_name":"Exchangy",'+update
        update = str(update.split('"}}')[0])+'"}}'
      except:
        err = '>> ERROR: update package seems corrupt (1)'
        skippy = True
      break
  if (skippy == False):
    # better re-check for corrupt update package before we patch the file
    if (update[0:12] == '{"toolinfo":' and update[-3:] == '"}}'):
      patcher = "db = '"+update+"'\n"
      with open(__file__,"r") as exchangy:
        sourcecode = exchangy.read()
      saucecode = sourcecode # store sauce in tmp var to prevent overwriting original sauce with re.sub()
      patchprobe = re.sub("db = '({.*?)}}'\n",patcher,saucecode)
      # are we up to date already?
      if (patchprobe == sourcecode):
        print('** Nothing to patch, we\'re up to date! ')
      else:
        print('** Update found, patching \''+str(__file__)+'\' ...')
        # Ok we're ready, patching now ... (hopefully nothing will break lol)
        try:
          with open(__file__,"w") as exchangy:
            patch = exchangy.write(re.sub("db = '({.*?)}}'\n",patcher,sourcecode))
        except:
          err = '>> ERROR: cannot patch tools internal db (write protected?)'
    else:
      err = '>> ERROR: update package seems corrupt (2)'
  return err


def init():
# parse option args and load prepare init
  global owa, target, port, host, enterMode, skipOnline, owaConfirmed
  target = ''
  rport = ''
  options = args()
  opthalp = options[0]
  opttrgt = options[1]
  optport = options[2]
  optskip = options[3]
  optupdt = options[4]
  optentr = options[5]
  if (opthalp != 0):
  # Check if help was called
    print('** Printing halp page')
    print('** Exchangy (v1.01) - ')
    print('   Exchange Server version & patchlevel detection')
    print('   -------------------------------------------------')
    print('   -h    get help (basically this)')
    print('   -t .. optional: set target (e.g. mail.url.com)')
    print('   -p .. optional: set custom port (default is 443)')
    print('   -s    optional: skip targets online check')
    print('   -u    optional: skip tools database update')
    print('   -e    optional: enter build number manually')
    print('   -------------------------------------------------')
    print('** Detections are runtime updated, but tool not. For tool go here:')
    print('   https://github.com/Haxel0rd/haxel0rds/tree/master/tools/exchangy')
    print('>> A message will be shown when a new tool version is available!')
    print('** Bug reports please to: twitter.com/haxel0rd')
    print('** Halp successfully delivered, exiting ...')
    sys.exit('** May the force be with you.\n\n')
  # Check if tools internal db is working, if yes, init as load json
  try:
    msdb = json.loads(db)
  except:
    print('\n** CRITICAL: tools internal db is broken!')
    print('   Please fetch a fresh download of Exchangy at: ')
    print('   https://github.com/Haxel0rd/haxel0rds/tree/master/tools/exchangy')
    print('   then retry by skipping the database update with -u. If this error')
    print('   persists for over a few days, please contact the tools author at:')
    print('   https://www.twitter.com/haxel0rd - Thank you.\n')
    sys.exit('** May the force be with you.\n\n')
  # Check for database updates on Exchange Versions
  if (optupdt == 0): # 0 for false, user did not choose to skip update
    print('** Checking for detection updates ...')
    updated = update(msdb)
    if (updated != ''):
      print(updated) # errormessage
      print('** Skipping update sequence (fallback to last state)')
  else: 
    print('** Skipping tools db update (-u)')
    print('   NOTE: you may miss detections if tool\'s not up to date!')
  # fetch number of detections and last patchlevel state
  icounter = -2 # number of different patchlevels detected, minus the first two entries
  for item in msdb:
    icounter+=1
  print('** Currently covering <'+str(icounter)+'> different patchlevels,') 
  print('   Latest Patchlevel: '+msdb[str(icounter)]["name"]+', '+msdb[str(icounter)]["release"])
  # Check if new >tool< update is available (not detection update)
  try:
    # will silently fail if update skipped 
    newVersion = json.loads(update)
    newVersion = newVersion["toolinfo"]["tool_version_latest"]
    if (newVersion != ExchangyVersion):
      print('>> Exchangy '+newVersion+' is available (-h for link)')
  except Exception as err:
    e = err # Not needed, but fixed weird try/catch behavior
  # Check if we run in "enter" mode, where we manually enter the OWA build number
  if (optentr == 1):
    enterMode = True
    while True:
      invalid = False
      usr = input('** Enter OWA build number manually (-e): ')
      if not usr:
        print('>> ERROR: invalid input')
        print('   must enter OWA build number ')
        invalid = True        
      if (len(str(usr)) > 16 and invalid == False):
        print('>> ERROR: invalid format')
        print('   number looks to long, try again cowboy ...')
        invalid = True
      if (len(str(usr)) < 5 and invalid == False):
        print('>> ERROR: invalid format')
        print('   number looks to short, try again cowboy ...')
        invalid = True
      if (re.search('[^0-9.]',usr) != None and invalid == False): 
      # reverse lookup (search chars that are not number or dot)
        print('>> ERROR: invalid input,')
        print('   only numbers and dots are allowed, try again cowboy ...')
        invalid = True
      if (invalid == False):
        owaConfirmed = True # ...otherwise we run into detection issues later
        owa = usr
        mslookup()
        rgen()
        sys.exit()
  # Is target given? if not prompt user, then parse target
  if (options[1] == ''):
    target = input('** Set target: ')
  else:
    target = options[1]
  try:
    target = target.split('//')[1]
  except:
    pass
  try: # we need to seperate the try's here as otherwise we run into a logic flaw
    target = target.split('/')[0]
  except:
    pass
  try: # this ones incase we have ip + port
    rport = target.split(':')[1]
    target = target.split(':')[0]
  except:
    pass
  target = target.replace('http://','')
  target = target.replace('https://','')
  if (rport != ''): # ..again if we have ip + port
    try:
      int(rport) # 
    except:
      print('>> ERROR: malformed port, must be number')
      print('   Sorry we can\'t continue, exiting ...')
      sys.exit('** May the force be with you.\n\n')
    port = int(rport)
    optport = 0 # "if" indictator for next port check
    prt = '   Port   set to:  '+rport+' (custom)'
  # Check if custom port was given (else, default to 443 or use port given in target url)
  if (optport == ''):
    prt = '   Port   set to:  443 (default)'
  else:
    if (optport != 0):
      try:
        port = int(optport)
      except:
        print('>> ERROR: malformed port, must be number')
        print('   Sorry we can\'t continue, exiting ...')
        sys.exit('** May the force be with you.\n\n')
      if (port > 65535 or port < 1):
        print('>> ERROR: port must range between 1-65535')
        print('   Sorry we can\'t continue, exiting ...')
        sys.exit('** May the force be with you.\n\n')
      prt = '   Port   set to: '+str(optport)+' (custom)'
  host = (target,port)
  # Drop initialize msg
  if (target == ''):
    print('>> ERROR: malformed target address')
    print('   Must be URL or IP adress (custom ports are ok)')
    print('   Sorry we can\'t continue, exiting ...')
    sys.exit('** May the force be with you.\n\n')
  print('** Initializing fingerprinting process ...')
  print('   Target set to:  '+target)
  print(prt)
  # check if target is online
  if (optskip == 0): # 1 for true, user skipped update
    print('** Sending probes to check if target is online',end='\r')
  else:
    skipOnline = True
    print('** Skipping target online probe (-s)')
  ison()
  # All configuration is done now, ready for checks...


def ison():
# check if target is online
  isOnline = False
  if (skipOnline == False):
    host = (target,port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
      s.settimeout(3)
      s.connect(host)
      s.shutdown(1)
      s.close()
      isOnline = True
    except:
      pass
    if (isOnline == False):
      try:
        packet = onc_packet.replace('{{target}}',target)
        onc_response = netw(packet)
        checkmatch = re.search('HTTP/1.[0-9] ([0-9]{1,3}) ',onc_response)
        if checkmatch:
          isOnline = True
      except:
        pass
    if (isOnline == True):
      print('** Online probe: target is online              ') # flush leftover char of prior line 
    else:
      print('** Target looks unavailable at given address, if you')
      print('   believe this is an error, re-run the tool with -s')
      print('   to skip targets online check.')
      print('   Sorry we can\'t continue, exiting ...')
      sys.exit('** May the force be with you.\n\n')


def checks():
# check owa method 1, logon.aspx
  global owa, owaConfirmed, office365
  owaConfirmed = False
  print('** Connecting to target server ...',end='\r')
  packet = owa_packet.replace('{{target}}',target)
  owa_response = netw(packet)
  if (owa_response == ''):
    print('>> ERROR: connection issues with target Server :(')
    print('   This only happens when target is not running anything')
    print('   on a given port or address, or sometimes when we get')
    print('   Firewalled or target is corrupted. (should happen rarely).')
    print('   Sorry we can\'t continue, exiting ...')
    sys.exit('** May the force be with you.\n\n')    
  else:
    # We're maybe daling with Office365, need a different request for this
    # (passed on the idea of checking this from target link as this wouldn't be reliable)
    print('** Firing build number checks at target server ...',end='\r')
    office365_packet = packet.replace('GET /owa/auth/logon.aspx HTTP','GET /adfs/ls/ HTTP')
    office365_response = netw(office365_packet)
    office365_regex = re.search('("/adfs/)(ls/|portal/)',str(office365_response))
    if office365_regex:
      print('** Office365 was detected on target server ...      ')
      office365 = True
      mslookup()
      rgen()
    owa_regex_cnf1 = re.search('<!-- OwaPage = ASP\.auth_logon_aspx -->',str(owa_response))
    owa_regex_cnf2 = re.search('/owa/',str(owa_response))
    owa_regex_gbn1 = re.search('\"/owa/([0-9]{1,}\.[0-9]{1}\.[0-9]{3,}(.{1,}|))/themes/',str(owa_response))
    owa_regex_gbn2 = re.search('\"/owa/auth/([0-9]{1,}\.[0-9]{1}\.[0-9]{3,}(.{1,}|))/themes/',str(owa_response))
    if owa_regex_cnf1:
      owaConfirmed = True
      print('** Found OWA panel, looking for build number          ')
    if (owa_regex_cnf2 and not owa_regex_gbn1 and owaConfirmed == False):
      # we are <maybe> dealing with owa, not sure as build number could not be extracted yet...
      print('** Couldn\'t detect OWA panel, sending more checks')
    if owa_regex_gbn1:
      print('** Build number found, trying Exchange version next')
      owa = owa_regex_gbn1.group(1).split('/')[0]
      owaConfirmed = True
    else:
      if (owaConfirmed == True):
        if owa_regex_gbn2:
          print('** Build number found, trying Exchange version next')
          owa = owa_regex_gbn2.group(1).split('/')[0]
        else:
          print('** No build number found yet, maybe dealing with Firewall')
          print('   or panel was obfuscated by admins.. trying to bypass')
          check2 = owa2() 
      else:
        print('** Nothing found yet, retrying with different approach')
        check2 = owa2() 


def owa2():
# nothing found in first run, fire a second round with different approach
  global owa, owaConfirmed, office365
  packet = owa_packet.replace('/owa/auth/logon.aspx','https://'+str(target)+'/owa/auth/errorfe.aspx')
  # Intentionally added full url for this 2nd try request
  owa_response = netw(packet)
  protected = re.search('Please enable JavaScript to view the page content',str(owa_response))
  if protected:
    print('>> ALERT: Targetsite is using WAF protection!') 
    print('   We mostly can\'t bypass this atm, it may be added in')
    print('   future versions, but this case occurs rarely anyways.')
    print('   Try adding build number manually with -e ')
    # Sometimes we can't bypass F5 Networks JS detection, i may look into that oneday but 
    # this situation occurs rarely at the time of writing, so no won't invest further time into this.
  owa_regex_gbn1 = re.search('\"/owa/auth/([0-9]{1,}\.[0-9]{1}\.[0-9]{3,}(.{1,}|))/themes/',str(owa_response))
  if not owa_regex_gbn1:
    # 3rd method, raising server exception, re-using url from method 2, 
    # calling non existant .aspx file (we barely need this), will result in owa build number leak:
    owa_regex_gbn2 = re.search('\"/owa/([0-9]{1,}\.[0-9]{1}\.[0-9]{3,}(.{1,}|))/themes/',str(owa_response))
    if not owa_regex_gbn2:
      print('** Unable to pull build number from target :(')
      if (owaConfirmed == False):
        print('   (maybe not an Exchange Server or we\'re Firewalled)')
      else:
        print('   Try adding build number manually with -e ')
      print('   Sorry we can\'t continue, exiting ...')
      sys.exit('** May the force be with you.\n\n')
    else:
      print('** Build number found, trying Exchange version next')
      owa = str(owa_regex_gbn2.group(1)).split('/themes')[0]
      owaConfirmed = True
  else:
    print('** Build number found, trying Exchange version next')
    owa = str(owa_regex_gbn1.group(1)).split('/themes')[0]
    owaConfirmed = True


def mslookup():
# lookup msdocs for owa build numbers
  global owa, xch, plv, rls, xchConfirmed
  msdb = json.loads(db)
  if (office365 == True):
    xch = 'Office 365'
    plv = '(not Exchange)'
    rls = '/'
    owa = '/'
  else:
    if (owa != ''):
      for item in msdb:
        try:
          if re.search(owa,msdb[item]["buildno_s"]):
            if (owaConfirmed == True):
              xch = msdb[item]["name"]
              plv = msdb[item]["release"]
              rls = msdb[item]["date"]
              owa = msdb[item]["buildno_s"]
              xchConfirmed = True
              break
            else:
              pass
        except:
          pass
      if (xchConfirmed == False):
      # No luck in first try, fire a second round with minified version number
        tmp = owa+'y'                         
        tmp = re.sub('\.[0]{1,4}\.','.x.',tmp)
        tmp = re.sub('\.[0]{1,4}[y]','.x',tmp)
        tmp = tmp.replace('.0','.').replace('.0','.').replace('.0','.')
        tmp = tmp.replace('y','')
        tmp = tmp.replace('x','0') # unelegant but smart way to handle this, saved lines of code and logic
        for item in msdb:
          try:
            if re.search(tmp,msdb[item]["buildno_s"]):
              xch = msdb[item]["name"]
              plv = msdb[item]["release"]
              rls = msdb[item]["date"]
              owa = msdb[item]["buildno_s"]
              xchConfirmed = True
              break
          except:
              pass
      if (xchConfirmed == False):
      # last try, taking away the last number of the buildid and see if we match then...
        tmp = tmp.rsplit('.',1)[0]
        for item in msdb:
          try:
            if re.search(tmp,msdb[item]["buildno_s"]):
              xch = msdb[item]["name"]
              plv = msdb[item]["release"]
              rls = msdb[item]["date"]
              owa = msdb[item]["buildno_s"]
              xchConfirmed = True
              break
          except:
              pass      
      if (xchConfirmed == False):
        xch = '<unknown>'
        plv = '<unknown>'
        rls = '<unknown>'
        if (owa == ''): 
          owa = '<unknown>'
        if (enterMode == True):
          owa = owa+'  (-e)'
    else: # Failsafe exit, incase we miss the first one for some unexpected reason
      print('** Unable to pull build number from target :(')
      print('   Sorry we can\'t continue, exiting ...')
      sys.exit('** May the force be with you.\n\n')


def rgen():
# WE ARE DONE - printing the results 
  err_reason = ''
  print('** Done, printing out gathered informations:')
  print('   ---------------------------------------------')
  print('   > Exchange version:  '+xch)
  print('   > Patchlevel:        '+plv)
  print('   > Release Date:      '+rls)
  print('   > Buildnumber:       '+owa)
  print('   ---------------------------------------------')
  if (xch == '<unknown>' and owa != '<unknown>'):
    print('** Could not retrieve Exchange version,')
    print('   requires manual research of build number.')
    print('** All checks performed, exiting.')
    sys.exit('** May the force be with you.\n\n')
  elif (xch != '<unknown>' and owa == '<unknown>'):
    print('** Could not retrieve Exchange version,')
    print('   the target may be customized to heavily.')
    print('   You can try adding build number manually (-e)')
    print('** All checks performed, exiting.')
    sys.exit('** May the force be with you.\n\n')
  elif (owa == '/'):
    print('** Target runs Office365 via ADFS Single Sign-on')
    print('   (no Exchange, mailing is hosted by Microsoft).')
    print('** All checks performed, exiting.')
    sys.exit('** May the force be with you.\n\n')
  else:
    print('** All checks performed, exiting.')
    sys.exit('** May the force be with you.\n\n')


def netw(packet):
# networking functions based on raw sockets.. from Haxe with <3
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
      sock.settimeout(7)
      sock.connect(host)
      sock.send(packet.encode("utf-8"))
      i = 0;
      e = 0;
      while i < 1337: # Limited rounds to prevent getting stuck in loops when no EOF
        chunk = str(sock.recv(4096))
        response += chunk
        response = response.replace('\\r\\n','').replace('\r\n','')
        if re.search('</body></html>',str(response)) != None:
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
      err = re.search('\[Errno ([0-9].+)\]',str(sockerr))
      unfound+=1
    except socket.timeout:
      print('** ERROR sending packet: timeouted (target online?)')
      print('   Sorry we can\'t continue, exiting ...')
      sys.exit('** May the force be with you.\n\n')
  return response


def Exchangy():
  # program flow:
  # banner()  called at start
  init()
  # update()  called by init()
  # ison()    called by init()
  checks()
  # owa2()    called by checks()
  mslookup()
  rgen()
# Entrypoint
# ----------  
Exchangy()
# ----------
