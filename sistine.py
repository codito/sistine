#!/usr/bin/python
'''
Sistine | Sify Authentication Daemon
By Liet-Kynes
Mod by Arun

A feint, within a feint, within a feint

Last Modified: Sat 01 Nov 2008 12:54:38 AM IST
'''

import sys
import httplib,urlparse
import re
import os
import subprocess as sp
import socket,struct
import hashlib
import xml.dom.minidom
from xml.dom.minidom import Node

#======================================================================

gUsername='my_username'
gPassword='my_password'

#The authentication host (coincides with the client download server)
#The value is hardcoded in Sify's client, so its improbable that it
#will vary
gCommHost = '202.144.65.70:8090'

#This string is a result of an asinine method used by the Sify client
#It appears to serve the mere purpose of either padding the generator
#key strings, or introducing a bit of garbage. This string is composed
#of two separate elements : The first half is 3654egf^@q|$ds!as87&#.
#This string is hardcoded in BBAppDll.dll, and returned by the Crosier
#method. A quick glance will reveal that the second half is formed by
#taking alternate characters from the first half. So, if they change the
#string returned by Crosier, you know what to do.
gConstKey='3654egf^@q|$ds!as87&#%35ef@|d!s7#'

#Another hardcoded hex key that appears to serve the sole purpose of
#padding the source plaintext
gConstHex='29355d121c211de0717c127166713ebb'
#======================================================================


gClientVersion='3.22'

gMacAddr=''
gSysIP=''
gUserAgent='BBClient'
#======================================================================

# Values returned by the Sify Auth Server
# These are the only values I found worth isolating, but its pretty
# trivial to modify the XML parser to get the rest of the values

gPvtIP=''
gSessionID=''
gServerTime=''
gLoginURL=''
gIsActiveURL=''
gLogoutURL=''

#======================================================================

def getProcStdOut(cmd):
    conPipe = sp.Popen(cmd, stdout=sp.PIPE,shell=True)
    conOut = conPipe.communicate()[0]    
    return conOut


def getMACAddress():
    global gMacAddr
    sysIP=socket.gethostbyaddr(socket.gethostname())[2]
    if os.name=='nt':
        conOut=getProcStdOut("ipconfig /all")
        conOut='@'.join([phi for phi in conOut.splitlines()])
        m = re.search('.*Physical Address.*?: (.*?)@.*IP Address.*?: %s.*'%sysIP,conOut)
        gMacAddr=m.group(1).strip().lower()
    else:
        conOut=getProcStdOut("ifconfig")
        conOut='@'.join([phi for phi in conOut.splitlines()])
        m = re.search('.*HWaddr (.*?)@.*inet addr:%s.*'%sysIP,conOut)
        gMacAddr=m.group(1).strip().lower()
    return gMacAddr


def getNetAddress(iDotAddr):
    return `struct.unpack('!L',socket.inet_aton(iDotAddr))[0]`

def getServerReply(destIP,destPath,msgBody=None,method='POST'):

    if msgBody==None:
        method='GET'
    method=method.upper()
    h = httplib.HTTPConnection(destIP)
    h.putrequest(method,destPath)
    if method=='POST':
        h.putheader('content-type','application/x-www-form-urlencoded')
        h.putheader('content-length',str(len(msgBody)))
    h.putheader('User-Agent',gUserAgent)
    h.endheaders()
    if method=='POST':
        h.send(msgBody)
    r=h.getresponse()
    return r.read()


def getServerParamMethodA():
    body='macaddress='+gMacAddr+'&srcip=192.168.1.3&version=3.22&os=xp'
    xmlCode=getServerReply(gCommHost,'/',body)
    parseInitXML(xmlCode)

def getServerParamMethodB():
    xmlCode=getServerReply(gCommHost,'/')
    parseInitXML(xmlCode)

def parseInitXML(xmlCode):
    global gPvtIP,gSessionID,gServerTime,gLoginURL,gIsActiveURL,gLogoutURL
    doc=xml.dom.minidom.parseString(xmlCode)

    for node in doc.firstChild.firstChild.childNodes:
        if node.nodeName=='LoginURL':
            gLoginURL=node.firstChild.data
        elif node.nodeName=='pvtIP':
            gPvtIP=node.firstChild.data
        elif node.nodeName=='ServerTime':
            gServerTime=node.firstChild.data
        elif node.nodeName=='sessionID':
            gSessionID=node.firstChild.data
        elif node.nodeName=='Urls':
            gLogoutURL=node.getElementsByTagName('Logout')[0].getAttribute('url')
        elif node.nodeName=='IsActiveUser':
            gIsActiveURL=node.firstChild.data

'''
Calculates the key used for encrypting the password
'''    
def calculateBlowfishKeyAlpha(sessionID):
    global gPvtIP
    netString=getNetAddress(gPvtIP)
    srcKey=gConstKey+netString+sessionID
    m = hashlib.md5(srcKey)
    bfKey = m.hexdigest()
    return bfKey

'''
Encrypts using the modified blowfish algorithm
The version used by Sify is a very slight deviation
from the original algorithm, and basically involves
changes to the S-boxes and P-arrays. See the C source
code for more info
'''
def blowfishEncrypt(plaintext,key):
    return getProcStdOut(os.getcwd()+'/modBlowfish "'+plaintext+'" '+key)

'''
The timestamp algorithm used by Sify
Assume the date and time to be integers
and get their difference. do an itoa on the
difference, then create a string with the ASCII
codes of the numbers in the difference string.

Mabey the coder was on weed...
'''
def genTimestamp(serverTime):
    (sDate,sTime)=serverTime.split()
    dateVec=sDate.split("-")
    dateStr=''.join([phi for phi in dateVec])
    timeVec=sTime.split(":")
    timeStr=''.join([phi for phi in timeVec])
    delta=int(dateStr)-int(timeStr)
    tstamp=''.join([`int(phi)+0x30` for phi in `delta`])
    return tstamp

'''
Calculate the key used for encrypting the final
authentication string
'''
def calculateBlowfishKeyBeta(sessionID,serverTime):
    global gPvtIP
    tstamp=genTimestamp(serverTime)
    txtKey=gConstKey+tstamp+getNetAddress(gPvtIP)+sessionID
    m = hashlib.md5(txtKey)
    bfKey = m.hexdigest()
    return bfKey

'''
Create the authentication string
'''
def formConnPlaintext(sessionID,username,password):
    global gPvtIP
    bfKey=calculateBlowfishKeyAlpha(sessionID)
    encPasswd=blowfishEncrypt(password,bfKey)
    connText='%s|%s|%s|%s|%s|%s|%s'%(username,encPasswd,gPvtIP,gMacAddr,gClientVersion,sessionID,gConstHex)
    return connText

def sistineError(msg):
    print 'Sistine Error : ' + msg
    sys.exit(1)

def sistineInfo(msg):
    print 'Sistine Info : ' + msg

def sistineDebug(msg):
    print '__DEBUG__ : ' + msg

def parseLoginXML(xmlCode):
    doc=xml.dom.minidom.parseString(xmlCode)
    for node in doc.firstChild.firstChild.childNodes:
        if node.nodeName=='ResponseCode':
            if node.firstChild.data!='0':
                sistineError('Login Unsuccessful')
            else:
                sistineInfo('Authentication Successful')
        elif node.nodeName=='ReplyMessage':
            print 'Server Reply : ' + node.firstChild.data

def parseLogoffXML(xmlCode):
    doc=xml.dom.minidom.parseString(xmlCode)
    for node in doc.firstChild.firstChild.childNodes:
        if node.nodeName=='ResponseCode':
            if node.firstChild.data!='150':
                sistineError('Logout Unsuccessful')
            else:
                sistineInfo('Logout Successful')
        elif node.nodeName=='ReplyMessage':
            print 'Server Reply : ' + node.firstChild.data

'''
Send in the authentication string and the mac addresss
(Observe that useless redundancy doesn't bother 'em)
...and 'cons'! Could it be that they have a LISP coder
at sify?? Naaah, probably 'connection string' or something
'''
def secureAuthenticate(username,password):
    getServerParamMethodA()
    plainText=formConnPlaintext(gSessionID,username,password)
    sistineDebug('Connection String : ' + plainText)
    bfKey=calculateBlowfishKeyBeta(gSessionID,gServerTime)
    sistineDebug('Blowfish Key : ' + bfKey)
    cons=blowfishEncrypt(plainText,bfKey)
    authReq='cons='+cons #+'&macaddress='+gMacAddr
    sistineDebug('Encrypted Connection String : ' + authReq)
    phi=urlparse.urlparse(gLoginURL)
    servXML=getServerReply(phi.netloc,phi.path,authReq)
    parseLoginXML(servXML)

'''
Send a logout request to the server
'''
def insecureLogoff():
    getServerParamMethodA()
    authReq='username='+gUsername+'&srcip='+gPvtIP
    authReq+='&macaddress='+gMacAddr+'&version='+gClientVersion
    authReq+='&sessionid='+gSessionID
    phi=urlparse.urlparse(gLogoutURL)
    servXML=getServerReply(phi.netloc,phi.path,authReq)
    parseLogoffXML(servXML)

'''
Obsolete authentication method
Coded just for the heck of it
'''
def insecureAuthenticate(username,password):
    sysIP=socket.gethostbyaddr(socket.gethostname())[2]
    authReq='username=%s&password=%s&srcip=%s&macaddress=%s&sessionid=%s'%(username,password,sysIP,gMacAddr,gSessionID)
    phi=urlparse.urlparse(gLoginURL)
    print authReq
    print getServerReply(phi.netloc,phi.path,authReq)


def main():    
    getMACAddress()
    #Spoof MAC
    #gMacAddr='00-11-22-33-44-55'.lower() #LOWER!!!!!!!!!

    if len(sys.argv)!=2:
        sistineError("usage: sistine (in|out)")
        sys.exit(1)
    else:
        arg=sys.argv[1]

    if arg=='in':
        secureAuthenticate(gUsername,gPassword)
    elif arg=='out':
        insecureLogoff()
    else:
        sistineError("usage: sistine (in|out)")
        sys.exit(1)

main()
