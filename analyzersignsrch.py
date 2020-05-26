from ida_defines import *
import subprocess
from utils import Utils

class AnalyzerSignSrch():

    ################################################################################################
    
    def __init__(self, signSearchPath, gPrinter):
        self.signSearchPath = signSearchPath
        self.gPrinter = gPrinter
    
    ################################################################################################    
    
    def Analyze(self, targetBinPath):
        retval = []
        output = subprocess.check_output([self.signSearchPath, "-e", targetBinPath], shell=True)
        l = output.split("--------------------------------------------\r\n")[1].split("\r\n")
        for e in l:
            if not len(e):
                break
            while e[0]==" ":
                e = e[1:]
            retval.append((int(e[0:e.index(" ")], 16), e[e.index(" ")+1:]))
        return retval
    
    ################################################################################################    

    def SignSrchToIdb(self):
        self.gPrinter.doPrint("SignSrch results", "signsrch")
        self.gPrinter.doPrint("----------------------------------------------------------", "signsrch")
        exePath = Utils.GetExePath()
        if exePath:
            l = self.Analyze(exePath)
            for e in l:
                self.gPrinter.doPrint("%x - SignSrch(%s)" % e, "signsrch")                
                cmt = IDAAPI_CommentEx(IDAAPI_ItemHead(e[0]), 1)
                if cmt==None:
                    cmt=""
                if e[1]!="" and e[1] not in cmt:
                    IDAAPI_MakeRptCmt(IDAAPI_ItemHead(e[0]), "%s SignSrch(%s)" % (cmt, e[1]))
        else:
            print("SignSrch not exe")
        self.gPrinter.doPrint("----------------------------------------------------------", "signsrch")
        self.gPrinter.doPrint("", "signsrch")
        self.gPrinter.doPrint("", "signsrch")
