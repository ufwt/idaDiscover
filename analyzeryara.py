from ida_defines import *
from installation import Installation
import os

class AnalyzerYara():

    ################################################################################################

    def __init__(self, yaraRulesPath, gPrinter):
        self.gPrinter = gPrinter
        print("Using yara rules: %s" % yaraRulesPath)
        self.yaraRulesPath = yaraRulesPath
        self.yaraRulesPathDirectory = os.path.dirname(os.path.realpath(self.yaraRulesPath))
        try:
            self.yaramod = __import__("yara")
        except:
            print("Error importing yara module. Please execute installation")
        curDirectory = os.getcwd()
        os.chdir(self.yaraRulesPathDirectory)
        try:
            self.rule = self.yaramod.compile(self.yaraRulesPath, includes=True, include_callback=Installation._incl_callback)
        except:
            print("Error compiling yara rules")
        os.chdir(curDirectory)
        
    ################################################################################################
        
    def Analyze(self, data, callback):
        try:
            self.rule.match(data=data, callback=callback)
        except Exception as e:
            print("Error in yara match %s" % e)

    ################################################################################################
    
    def YaraCallback(self, data):
        try:
            if data['matches'] == True:
                #print data['rule']
                for e in data['strings']:
                    if "contentis_base64" not in data['rule']:
                        cmt = IDAAPI_CommentEx(IDAAPI_ItemHead(self.currentEa+e[0]), 1)
                    if cmt==None:
                        cmt=""
                    if ("%s(%s)" % (data['rule'], e[1])) not in cmt:
                        IDAAPI_MakeRptCmt(IDAAPI_ItemHead(self.currentEa+e[0]), "%s yara(%s(%s))" % (cmt, data['rule'], e[1]))
                    self.gPrinter.doPrint("%x - yara(%s(%s))" % (self.currentEa+e[0], data['rule'], e[1]), "yara")
        except:
            pass
        self.yaramod.CALLBACK_CONTINUE
        
    ################################################################################################
    
    def YaraMatchesToIdbBySegments(self):
        self.gPrinter.doPrint("Yara matches:", "yara")
        self.gPrinter.doPrint("----------------------------------------------------------", "yara")
        for seg_ea in IDAAPI_Segments():
            self.currentEa = seg_ea
            self.currentEaEnd = IDAAPI_SegEnd(seg_ea)
            for i in range(0, 0x1000):
                flags = IDAAPI_GetFlags(self.currentEaEnd-1)
                if flags == 0 or flags == 512: #FF_UNK / FF_TAIL
                    self.currentEaEnd = self.currentEaEnd - 1
            segmentContent = IDAAPI_GetManyBytes(self.currentEa, self.currentEaEnd - self.currentEa)
            if not segmentContent:
                print("Unable to get segment content %x" % self.currentEa)
            else:
                print("Yara analysis on segment %x - %x" % (self.currentEa, self.currentEaEnd))
            if segmentContent:
                self.Analyze(segmentContent, self.YaraCallback)
        self.gPrinter.doPrint("----------------------------------------------------------", "yara")
        self.gPrinter.doPrint("", "yara")
        self.gPrinter.doPrint("", "yara")

    ################################################################################################
    
    def YaraMatchesToIdb(self):
        self.gPrinter.doPrint("Yara matches:", "yara")
        self.gPrinter.doPrint("----------------------------------------------------------", "yara")
        bfirst = True
        fullImage = ""
        for seg_ea in IDAAPI_Segments():
            if bfirst: self.currentEa = seg_ea
            else: fullImage += ("\x00"*(seg_ea - self.currentEaEnd))
            bfirst = False
            self.currentEaEnd = IDAAPI_SegEnd(seg_ea)
            removedBytes = 0
            for i in range(0, 0x1000):
                flags = IDAAPI_GetFlags(self.currentEaEnd - 1)
                if flags == 0 or flags == 512: #FF_UNK / FF_TAIL
                    self.currentEaEnd = self.currentEaEnd - 1
                    removedBytes += 1
            segmentContent = IDAAPI_GetManyBytes(seg_ea, self.currentEaEnd - seg_ea)
            if not segmentContent:
                print("Unable to get segment content %x" % seg_ea)
                fullImage += "\x00"*(self.currentEaEnd - seg_ea + removedBytes)
            else:
                print("Yara analysis on segment %x - %x" % (seg_ea, self.currentEaEnd))
                fullImage += (segmentContent + "\x00"*removedBytes)
            self.currentEaEnd += removedBytes
        self.Analyze(fullImage, self.YaraCallback)
        self.gPrinter.doPrint("----------------------------------------------------------", "yara")
        self.gPrinter.doPrint("", "yara")
        self.gPrinter.doPrint("", "yara")
