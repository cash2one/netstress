#!/usr/bin/python

# Metin KAYA <kayameti@gmail.com>
# 2012.05.25, Istanbul
# http://www.EnderUNIX.org/metin
#

import wx, os, sys, commands, paramiko


__author__ = 'Metin KAYA <kayameti@gmail.com>'
__version__ = '0.2'


def isValidIP(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for item in parts:
        if item.isdigit() is False or not 0 <= int(item) <= 255:
            return False
    return True


class NetStressPanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.dnsqtypeval    = 'A'
        self.attacktypeval  = 'ACK'
        self.srctypeval     = 'Static IP / Port'
        self.srcipval       = ''
        self.srcportval     = ''
        self.dstipval       = ''
        self.dstportval     = ''
        self.processnameval = 'netstress.fullstatic'
        self.numprocval     = '1'
        self.dnshost        = None
        self.useragent      = None
        self.username       = None
        self.password       = None
        self.hostname       = None
        self.port           = None
        self.portval        = '22'

        png = wx.Image('/usr/bin/netstress.jpg', wx.BITMAP_TYPE_ANY).ConvertToBitmap()
        wx.StaticBitmap(self, -1, png, (0, 0), (png.GetWidth(), png.GetHeight()))

        self.remoteMachineCB = wx.CheckBox(self, -1, "Run on Remote Machine:    ", (20, 15), (170, 30), style=wx.ALIGN_RIGHT)
        self.remoteMachineCB.SetForegroundColour('red')
        self.Bind(wx.EVT_CHECKBOX, self.EvtCB, self.remoteMachineCB)

        self.srctype = [ "Static IP / Port", "Random IP / Port", "Static IP / Random Port", "Random IP / Static Port" ]
        self.lblsrctype = wx.StaticText(self, label="Source IP/Port Type:", pos=(20, 60))
        self.lblsrctype.SetForegroundColour('white')
        self.editsrctype = wx.ComboBox(self, pos=(210, 55), size=(200, 30),
                                          value=self.srctype[0], choices=self.srctype,
                                          style=wx.CB_DROPDOWN | wx.CB_READONLY)
        self.Bind(wx.EVT_COMBOBOX, self.EvtSrcType, self.editsrctype)

        self.srcip = wx.StaticText(self, label="Source IP:", pos=(20, 105))
        self.srcip.SetForegroundColour('white')
        self.srcipbox = wx.TextCtrl(self, pos=(210, 100), size=(140, 30))
        self.srcipbox.SetBackgroundColour((255, 255, 197))
        self.Bind(wx.EVT_TEXT, self.EvtSrcIP, self.srcipbox)

        self.srcport = wx.StaticText(self, label="Source Port:", pos=(20, 145))
        self.srcport.SetForegroundColour('white')
        self.srcportbox = wx.TextCtrl(self, pos=(210, 140), size=(140, 30))
        self.srcportbox.SetBackgroundColour((255, 255, 197))
        self.Bind(wx.EVT_TEXT, self.EvtSrcPort, self.srcportbox)

        self.dstip = wx.StaticText(self, label="Destination IP:", pos=(20, 185))
        self.dstip.SetForegroundColour('white')
        self.dstipbox = wx.TextCtrl(self, pos=(210, 180), size=(140, 30))
        self.dstipbox.SetBackgroundColour((255, 255, 197))
        self.Bind(wx.EVT_TEXT, self.EvtDstIP, self.dstipbox)

        self.dstport = wx.StaticText(self, label="Destination Port:", pos=(20, 225))
        self.dstport.SetForegroundColour('white')
        self.dstportbox = wx.TextCtrl(self, pos=(210, 220), size=(140, 30))
        self.dstportbox.SetBackgroundColour((255, 255, 197))
        self.Bind(wx.EVT_TEXT, self.EvtDstPort, self.dstportbox)

        self.numproc = wx.StaticText(self, label="Number of Processes:", pos=(20, 265))
        self.numproc.SetForegroundColour('white')
        self.numprocbox = wx.TextCtrl(self, pos=(210, 260), size=(140, 30), value=self.numprocval)
        self.numprocbox.SetBackgroundColour((255, 255, 197))
        self.Bind(wx.EVT_TEXT, self.EvtNumProc, self.numprocbox)

        self.attacktype = ["ACK", "AMPDNS", "DNS", "FIN", "GET", "IGMP", "ISSSYN", "SYN",
                           "SYNCOOK", "UDP", "WINBOMP", "WIN98"]
        self.lblattacktype = wx.StaticText(self, label="Type of Attack:", pos=(20, 305))
        self.lblattacktype.SetForegroundColour('white')
        self.editattacktype = wx.ComboBox(self, pos=(210, 300), size=(140, 30),
                                          value=self.attacktype[0], choices=self.attacktype,
                                          style=wx.CB_DROPDOWN | wx.CB_READONLY)
        self.Bind(wx.EVT_COMBOBOX, self.EvtAttackType, self.editattacktype)  

        self.pids = wx.StaticText(self, pos=(20, 420))
        self.pids.SetForegroundColour('white')

        self.nsstat = wx.StaticText(self, pos=(20, 435))
        self.nsstat.SetForegroundColour('white')

        self.StartButton = wx.Button(self, label="Start", pos=(100, 550))
        self.StartButton.Bind(wx.EVT_BUTTON, self.EvtStart)

        self.StatusButton = wx.Button(self, label="Status", pos=(200, 550))
        self.StatusButton.Enable(False)
        self.StatusButton.Bind(wx.EVT_BUTTON, self.EvtStatus)

        self.StopButton = wx.Button(self, label="Stop", pos=(300, 550))
        self.StopButton.Enable(False)
        self.StopButton.Bind(wx.EVT_BUTTON, self.EvtStop)


    def EvtStart(self, event=None):
        if self.srctypeval == 'Static IP / Port' or self.srctypeval == 'Static IP / Random Port':
            if isValidIP(self.srcipval) is False:
                wx.MessageBox('Source IP address is not valid!', 'Error')
                return
        if self.srctypeval == 'Static IP / Port' or self.srctypeval == 'Random IP / Static Port':
            if self.srcportval.isdigit() is False or int(self.srcportval) < 1 or int(self.srcportval) > 65536:
                wx.MessageBox('Source port number is not valid!', 'Error')
                return
        if isValidIP(self.dstipval) is False:
            wx.MessageBox('Destination IP address is not valid!', 'Error')
            return
        if self.dstportval.isdigit() is False or int(self.dstportval) < 1 or int(self.dstportval) > 65536:
            wx.MessageBox('Destination port number is not valid!', 'Error')
            return
        if self.numprocval.isdigit() is False or int(self.numprocval) < 1:
            wx.MessageBox('Number of process is not valid!', 'Error')
            return

        params = " -d " + self.dstipval      + " -P " + self.dstportval \
               + " -a " + self.attacktypeval + " -n " + self.numprocval
        if self.srctypeval == 'Static IP / Port':
            params += " -p " + self.srcportval + " -s " + self.srcipval
        elif self.srctypeval == 'Static IP / Random Port':
            params += " -s " + self.srcipval
        elif self.srctypeval == 'Random IP / Static Port':
            params += " -p " + self.srcportval
        if self.attacktypeval == 'GET':
            params += " -u " + self.useragentval
        elif self.attacktypeval == 'DNS' or self.attacktypeval == 'AMPDNS':
            params += " -N " + self.dnshostval + " -t " + self.dnsqtypeval

        if self.remoteMachineCB.GetValue() is True:
            if self.portval.isdigit() is False or int(self.portval) < 1 or int(self.portval) > 65536:
                wx.MessageBox('SSH port number is not valid!', 'Error')
                return
            try:
                self.ssh = paramiko.SSHClient()
                self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.ssh.connect(self.hostnameval, int(self.portval), username=self.usernameval, password=self.passwordval)
                self.ssh.exec_command('sudo ' + self.processnameval + params)
                stdin, stdout, stderr = self.ssh.exec_command('sleep 1; pidof ' + self.processnameval)
                cmd_out = stdout.readlines()[0].split('\n')[0]
            except Exception, e:
                wx.MessageBox('Failed to run NetStress on remote machine: %s' % str(e), 'Error')
                return
        else:
            if sys.platform != "linux2":
                wx.MessageBox('NetStress does not run on %s! Please provide SSH parameters that has NetStress.' % os.name, 'Error')
                return
            print 'sudo ' + self.processnameval + params + ' &'
            os.system('sudo ' + self.processnameval + params + ' &')
            cmd_out = commands.getoutput('sleep 1; pidof ' + self.processnameval)

        if len(cmd_out) > 0:
            self.pids.SetLabel('NetStress has been started...')
            self.StartButton.Enable(False)
            self.StatusButton.Enable(True)
            self.StopButton.Enable(True)
        else:
            self.pids.SetLabel('Cannot start NetStress (%s)!' % self.processnameval)
        self.nsstat.SetLabel('')


    def EvtStatus(self, event=None):
        if self.remoteMachineCB.GetValue() is True:
            stdin, stdout, stderr = self.ssh.exec_command("pidof " + self.processnameval)
            cmd_out = stdout.readlines()[0].split("\n")[0]
            stdin, stdout, stderr = self.ssh.exec_command("sudo kill -1 " + cmd_out + ' && sleep 1 && cat /var/run/netstress.stat.*')
            data = stdout.readlines()
            cmd_out2 = ""
            for line in data:
                cmd_out2 += line.split("\n")[0] + "\n"
        else:
            cmd_out = commands.getoutput("pidof " + self.processnameval)
            os.system("sudo kill -1 " + cmd_out)
            cmd_out2 = commands.getoutput("cat /var/run/netstress.stat.*")

        self.pids.SetLabel("PID(s): " + cmd_out)
        self.nsstat.SetLabel(cmd_out2)


    def EvtStop(self, event=None):
        self.pids.SetLabel('NetStress has been stopped...')
        if self.remoteMachineCB.GetValue() is True:
            stdin, stdout, stderr = self.ssh.exec_command("pidof " + self.processnameval)
            cmd_out = stdout.readlines()[0].split("\n")[0]
            stdin, stdout, stderr = self.ssh.exec_command('sudo kill ' + cmd_out)
            self.ssh.close()
        else:
            cmd_out = commands.getoutput("pidof " + self.processnameval)
            os.system('sudo kill ' + cmd_out)
        self.nsstat.SetLabel('')
        self.StopButton.Enable(False)
        self.StatusButton.Enable(False)
        self.StartButton.Enable(True)


    def EvtCB(self, event=None):
        if self.remoteMachineCB.GetValue() is True:
            if self.hostname is None:
                self.hostname = wx.TextCtrl(self, pos=(240, 15), size=(140, 30), value='Hostname')
                self.hostname.SetBackgroundColour((255, 255, 197))
                self.Bind(wx.EVT_TEXT, self.EvtHostname, self.hostname)

                self.username = wx.TextCtrl(self, pos=(390, 15), size=(140, 30), value='Username')
                self.username.SetBackgroundColour((255, 255, 197))
                self.Bind(wx.EVT_TEXT, self.EvtUsername, self.username)

                self.password = wx.TextCtrl(self, pos=(540, 15), size=(140, 30), value='Password', style=wx.TE_PASSWORD)
                self.password.SetBackgroundColour((255, 255, 197))
                self.Bind(wx.EVT_TEXT, self.EvtPassword, self.password)

                self.port = wx.TextCtrl(self, pos=(690, 15), size=(60, 30), value='Port')
                self.port.SetBackgroundColour((255, 255, 197))
                self.Bind(wx.EVT_TEXT, self.EvtPort, self.port)
        else:
            if self.hostname is not None:
                self.hostname.Destroy()
                self.username.Destroy()
                self.password.Destroy()
                self.port.Destroy()
                self.hostname    = None
                self.username    = None
                self.password    = None
                self.port        = None


    def EvtSrcType(self, event=None):
        self.srctypeval = self.editsrctype.GetValue()
        if self.srctypeval == 'Static IP / Port':
            self.processnameval = 'netstress.fullstatic'
            self.srcipbox.Enable()
            self.srcportbox.Enable()
        elif self.srctypeval == 'Random IP / Port':
            self.processnameval = 'netstress.fullrandom'
            self.srcipbox.Disable()
            self.srcportbox.Disable()
        elif self.srctypeval == 'Static IP / Random Port':
            self.processnameval = 'netstress.staticip_randomport'
            self.srcipbox.Enable()
            self.srcportbox.Disable()
        else:
            self.processnameval = 'netstress.randomip_staticport'
            self.srcipbox.Disable()
            self.srcportbox.Enable()


    def EvtHostname(self, event=None):
        self.hostnameval = self.hostname.GetValue()


    def EvtUsername(self, event=None):
        self.usernameval = self.username.GetValue()


    def EvtPassword(self, event=None):
        self.passwordval = self.password.GetValue()


    def EvtPort(self, event=None):
        self.portval = self.port.GetValue()


    def EvtSrcIP(self, event=None):
        self.srcipval = self.srcipbox.GetValue()


    def EvtSrcPort(self, event=None):
        self.srcportval = self.srcportbox.GetValue()


    def EvtDstIP(self, event=None):
        self.dstipval = self.dstipbox.GetValue()


    def EvtDstPort(self, event=None):
        self.dstportval = self.dstportbox.GetValue()


    def EvtAttackType(self, event=None):
        self.attacktypeval = self.editattacktype.GetValue()
        if self.attacktypeval == 'GET':
            if self.dnshost is not None:
                self.dnshost.Destroy()
                self.dnshostbox.Destroy()
                self.lbldnsqtype.Destroy()
                self.editdnsqtype.Destroy()
                self.dnshost      = None
                self.dnshostbox   = None
                self.lbldnsqtype  = None
                self.editdnsqtype = None
            self.useragent = wx.StaticText(self, label='User Agent for GET Flood:', pos=(20, 345))          
            self.useragent.SetForegroundColour('white')
            self.useragentbox = wx.TextCtrl(self, pos=(210, 340), size=(140, 30))
            self.useragentbox.SetBackgroundColour((255, 255, 197))
            self.Bind(wx.EVT_TEXT, self.EvtUserAgent, self.useragentbox)
        elif self.attacktypeval == 'DNS' or self.attacktypeval == 'AMPDNS':
            if self.useragent is not None:
                self.useragent.Destroy()
                self.useragentbox.Destroy()
                self.useragent    = None
                self.useragentbox = None
            if self.dnshost is not None:
                return
            self.dnshost = wx.StaticText(self, label="Hostname for DNS Attack:", pos=(20, 345))
            self.dnshost.SetForegroundColour('white')
            self.dnshostbox = wx.TextCtrl(self, pos=(210, 340), size=(140, 30))
            self.dnshostbox.SetBackgroundColour((255, 255, 197))
            self.Bind(wx.EVT_TEXT, self.EvtDNSHost, self.dnshostbox)

            self.dnsqtype = ["A", "CNAME", "HINFO", "MINFO", "MX", "NS", "PTR", "SOA", "TXT", "WKS"]
            self.lbldnsqtype = wx.StaticText(self, label="Type of DNS Query:", pos=(20, 385))
            self.lbldnsqtype.SetForegroundColour('white')
            self.editdnsqtype = wx.ComboBox(self, pos=(210, 380), size=(140, 30), value=self.dnsqtype[0],
                                        choices=self.dnsqtype, style=wx.CB_DROPDOWN | wx.CB_READONLY)
            self.Bind(wx.EVT_COMBOBOX, self.EvtDNSQType, self.editdnsqtype)
        else:
            if self.useragent is not None:
                self.useragent.Destroy()
                self.useragentbox.Destroy()
                self.useragent    = None
                self.useragentbox = None
            if self.dnshost is not None:
                self.dnshost.Destroy()
                self.dnshostbox.Destroy()
                self.lbldnsqtype.Destroy()
                self.editdnsqtype.Destroy()
                self.dnshost      = None
                self.dnshostbox   = None
                self.lbldnsqtype  = None
                self.editdnsqtype = None


    def EvtNumProc(self, event=None):
        self.numprocval = self.numprocbox.GetValue()


    def EvtDNSHost(self, event=None):
        self.dnshostval = self.dnshostbox.GetValue()


    def EvtDNSQType(self, event=None):
        self.dnsqtypeval = self.editdnsqtype.GetValue()


    def EvtUserAgent(self, event=None):
        self.useragentval = self.useragentbox.GetValue()


if __name__ == '__main__':
    app = wx.App(False)
    frame = wx.Frame(None, title='NetStress v' + __version__, size=(1024, 650), style=wx.DEFAULT_FRAME_STYLE | wx.FULL_REPAINT_ON_RESIZE)
    panel = NetStressPanel(frame)
    frame.Show()
    frame.Centre()
    app.MainLoop()
