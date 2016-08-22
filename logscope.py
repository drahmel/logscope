#!/usr/bin/env python
# logscope v1.1 by Dan Rahmel
# (c) Copyright 2008-2016 by Dan Rahmel
# Created September 14, 2008

# Example usage:
# logscope.py c:\access.log --ip 127.0.0.1 -b2008,9,17,12,30,0
# logscope.py c:\access.log --text get_data
# logscope.py c:\access.log --ip 127.0.0.2
# logscope.py c:\access.log --resp 404
# logscope.py c:\access.log -b2008,7,3,8,30,0 -e2008,7,3,14,30,0
# logscope.py c:\access.log -b2008,7,3,8,30,0 -e2008,7,3,14,30,0 -t css
# logscope.py c:\logfilter.txt -t process_card
# logscope.py c:\logfilter.txt -t add_member_account
# logscope.py c:\logfilter.txt -i 204.108.100.244 -o c:\session_jddavid18.log
#

# Sample Apache log lines
#apacheLine1 = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"'
#apacheLine2 = '127.0.0.1 - - [01/Jun/2008:17:47:05 -0700] "GET /poc_web/lameloop.php HTTP/1.1" 200 146'
#junkLine = '[main]aksdjalksjd ka jsdlkaj sdkj'

def prRed(prt): print("\033[91m {}\033[00m" .format(prt))
def prGreen(prt): print("\033[92m {}\033[00m" .format(prt))
def prYellow(prt): print("\033[93m {}\033[00m" .format(prt))
def prLightPurple(prt): print("\033[94m {}\033[00m" .format(prt))
def prPurple(prt): print("\033[95m {}\033[00m" .format(prt))
def prCyan(prt): print("\033[96m {}\033[00m" .format(prt))
def prLightGray(prt): print("\033[97m {}\033[00m" .format(prt))
def prBlack(prt): print("\033[98m {}\033[00m" .format(prt))

import re, datetime, xml.dom.minidom,os
from time import strftime
from optparse import OptionParser
from time import strftime
from datetime import date

class logscope:
    def report(self,inStr):
        print inStr
    def getRev(self):
        revStr= "$Rev: 3 $"
        tempArray = revStr.split()
        return "1.0."+str(tempArray[1])
    def processDate(self,inStr,beginFlag):
        if beginFlag:
            dateMin = 0
            dateSec = 0
        else:
            dateMin = 59
            dateSec = 59

    def apacheParse(self,logFileStr,inAttr):
        # For the datetime parsing
        months = {'Jan':1, 'Feb':2, 'Mar':3, 'Apr':4, 'May':5, 'Jun':6, 'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}

        # Expressions to parse Apache logs
        exprFinal = r'[^0-9]*(?P<ip>\d+\.\d+\.\d+\.\d+) (?P<ident>[^ ]*) (?P<user>[^ ]*) \[(?P<date>[^\]]*)\] "(?P<req>[^"]*)" (?P<resp>\d+) (?P<respSize>[^ ]*)(?P<other>.*)'

        # Compile regular expression
        prog = re.compile(exprFinal)

        matches = 0
        notLogLine = 0
        outStr = ''
        fileList = {}
        # Setup fast boolean checks
        self.matchIP = True if inAttr.has_key('ip') else False
        self.matchResp = True if inAttr.has_key('resp') else False
        self.matchDates = True if inAttr.has_key('bdate') or inAttr.has_key('edate') else False
        self.matchRText = False
        if inAttr.has_key('rtext'):
            self.matchRText = True
            self.matchRTextStr = inAttr['rtext']
            self.matchRTextList = self.matchRTextStr.split(",")

        logFileList = logFileStr.split(",")
        exampleGood = False
        exampleBad = False
        for logFile in logFileList:
            try:
                f = open(logFile,'r')
            except (IOError, os.error), why:
                print "Can't read from file %s: %s" % (logFile, str(why))
                return

            count = 0
            limitLines = False
            for i, line in enumerate(f):
                if limitLines and count > limitLines:
                    break
                count += 1
                cleanLine = line
                # If log file is a combined log, it will have a denotation of the origin log followed by a :
                combinedMatch =  re.search(": \d+\.\d+\.\d+\.\d+", line)
                if combinedMatch:
                    # Shave off log anotation
                    cleanLine = line[(combinedMatch.start()+2):]
                result = prog.match(cleanLine)
                if result:
                    exampleGood = line
                    row = result.groupdict()
                    checksum = self.processLine(row)
                    if checksum.find('n')==-1 and len(checksum)>0:
                        aDate = row['date']
                        a = datetime.datetime(int(aDate[7:11]), months[aDate[3:6]], int(aDate[0:2]), int(aDate[12:14]), int(aDate[15:17]), int(aDate[18:20]))
                        if inAttr.has_key('outfile'):
                            outStr += line.strip() + "\n"
                        else:
                            print line.strip() #a.strftime("%y%m%d-%H:%M"),row
                            matches += 1
                else:
                    notLogLine +=1
                    #print line
                    exampleBad = line
            f.close()
        if inAttr.has_key('outfile'):
            try:
                output = open(inAttr['outfile'],'w')
                output.write(outStr)
                output.close()
            except (IOError, os.error), why:
                print "Can't read from file %s: %s" % (logFile, str(why))
                return
        print "Total lines in file:"+str(i+notLogLine)+" | Valid log lines:"+str(i)+" | Total matches:"+str(matches)
        if exampleGood:
            prGreen("Example good: " + exampleGood)
        if exampleBad:
            prRed(" Example bad: " + exampleBad)

    def processLine(self, row):
        checksum = ''
        if self.matchIP:
            if row['ip']==inAttr['ip']:
                checksum += 'y'
            else:
                checksum += 'n'
        if self.matchResp:
            if row['resp']==inAttr['resp']:
                checksum += 'y'
            else:
                checksum += 'n'
        # Check for specified text
        if self.matchRText:
            foundMatch = False
            for matchStr in self.matchRTextList:
                #if row['req'].find(inAttr['rtext'])!=-1:
                if row['req'].find(matchStr)!=-1:
                    foundMatch = True
                    break
            if foundMatch:
                checksum += 'y'
            else:
                checksum += 'n'
        # Check begin and end date
        if self.matchDates:
            aDate = row['date']
            logDateTime = datetime.datetime(int(aDate[7:11]), months[aDate[3:6]], int(aDate[0:2]), int(aDate[12:14]), int(aDate[15:17]), int(aDate[18:20]))
            if inAttr.has_key('bdate'):
                dtArray = inAttr['bdate'].split(',');
                beginDate = datetime.datetime(int(dtArray[0]), int(dtArray[1]), int(dtArray[2]), int(dtArray[3]), int(dtArray[4]), int(dtArray[5])) #datetime.datetime(2008, 6, 2)
                #print beginDate
                if logDateTime>=beginDate:
                    #print logDateTime,beginDate
                    checksum += 'y'
                else:
                    checksum += 'n'
            if inAttr.has_key('edate'):
                dtArray = inAttr['edate'].split(',');
                endDate = datetime.datetime(int(dtArray[0]), int(dtArray[1]), int(dtArray[2]), int(dtArray[3]), int(dtArray[4]), int(dtArray[5])) #datetime.datetime(2008, 6, 2)
                #endDate = datetime.datetime(2008, 7, 15)
                if logDateTime<=endDate:
                    checksum += 'y'
                else:
                    checksum += 'n'
        return checksum


    def run(self,options,args):
        print "--- LogScope, revision #"+self.getRev()+" --- "
        logFile = 'access_log'
        if(len(args)>0):
            logFile = args[0]
        attr = {}
        if options.ip:
            attr['ip']=options.ip
        if options.outfile:
            attr['outfile']=options.outfile
        if options.outsuffix:
            attr['outsuffix']=options.outsuffix
        if options.bdate:
            attr['bdate']=options.bdate
        if options.edate:
            attr['edate']=options.edate
        if options.resp:
            attr['resp']=options.resp
        if options.rtext:
            attr['rtext']=options.rtext
        if options.quietmode:
            attr['quietmode']=1
        if options.numlines:
            attr['numlines']=options.numlines

        print attr
        #self.apacheParse({'ip':'127.0.0.2','resp':'404','bdate':'2008,7,1,15,15,0','edate':'2008,7,1,16,30,00'})
        self.apacheParse(logFile,attr)

if __name__ == '__main__':
    logParse = logscope()
    usage = "usage: logscope [options] logfile(s)"
    parser = OptionParser(usage=usage)
    parser.add_option("-o", "--outfile", dest="outfile",help="output data to OUTFILE", metavar="OUTFILE")
    parser.add_option("-s", "--outsuffix", dest="outsuffix",help="Suffix to add to output filename", metavar="OUTSUFFIX")
    parser.add_option("-b", "--bdate", dest="bdate",help="Begin date for filter--comma delimited year,month,day,hour,min,sec", metavar="BDATE")
    parser.add_option("-e", "--edate", dest="edate",help="End date for filter--comma delimited year,month,day,hour,min,sec", metavar="EDATE")
    parser.add_option("-i", "--ip", dest="ip",help="IP address or addresses for filter", metavar="FILE")
    parser.add_option("-r", "--resp", dest="resp", help="Response type(200,404,etc.) for filter", metavar="RESP")
    parser.add_option("-t", "--text", dest="rtext", help="Respone text (filename,GET,POST) for filter", metavar="rtext")
    parser.add_option("-q", "--quiet",action="store_true", dest="quietmode", default=False,help="Turn off extra messages")
    parser.add_option("-n", "--num",action="store_true", dest="numlines", default=False,help="Limit to specified number of lines")
    (options, args) = parser.parse_args()
    logParse.run(options,args)

