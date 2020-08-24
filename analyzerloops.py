#
# idaDiscover plugin - by Javier Vicente Vallejo - @vallejocc
#

from ida_defines import *
from utils import Utils

class AnalyzerLoops():
    
    ################################################################################################
    
    def __init__(self, gPrinter):
        self.savedLoops = []
        self.savedFuncs = []
        self.bsavedLoopsInitialized = False
        self.gPrinter = gPrinter
        
    ################################################################################################
    
    @staticmethod
    def FastAnalysisLoop(ealoopstart, ealoopend):
        tags = []
        tagsdism = []
        stags = ""
        stagsdism = "   ///  "
        xormem = 0
        movmem = 0
        xor = 0
        shrl = 0
        incdec = 0
        andff = 0
        retcolor = None
        ea = ealoopstart
        while ea <= ealoopend:
            ins = IDAAPI_GetMnem(ea)
            op0 = IDAAPI_GetOpType(ea, 0)
            op1 = IDAAPI_GetOpType(ea, 1)
            dis = IDAAPI_GetDisasm(ea)
            if not movmem and ins=="mov" and (op0==3 or op0==4):
                    tags.append("movmem ")
                    tagsdism.append(dis)
                    movmem = 1
            if not xormem and ins=="xor" and (op0==3 or op0==4):
                    tags.append("xormem ")
                    tagsdism.append(dis)
                    xormem = 1
            if not xor and ins=="xor":
                    tags.append("xor ")
                    tagsdism.append(dis)
                    xor = 1
            if not shrl and (ins=="shr" or ins=="shl"):
                    tags.append("shrl ")
                    tagsdism.append(dis)
                    shrl = 1
            if not incdec and (ins=="inc" or ins=="dec"):
                    tags.append("incdec ")
                    tagsdism.append(dis)
                    incdec = 1
            if not incdec and (ins=="add" or ins=="sub") and (op1==5 or op1==6 or op1==7) and (IDAAPI_GetOperandValue(ea,1)==1 or IDAAPI_GetOperandValue(ea,1)==4):
                    tags.append("incdec ")
                    tagsdism.append(dis)
                    incdec = 1
            if not andff and ins=="and" and (op1==5 or op1==6 or op1==7) and IDAAPI_GetOperandValue(ea,1)==0xff:
                    tags.append("andff ")
                    tagsdism.append(dis)
                    andff = 1
            ea+=IDAAPI_ItemSize(ea)

        for e in sorted(tags):
            stags += e
        for e in sorted(tagsdism):
            stagsdism += (e + "  ///  ")
        if len(stags) and stags[-1]==" ": 
            stags=stags[0:-1]
        
        if movmem and xor: retcolor = 0xCCCCFF
        if xormem: retcolor = 0x9999FF
        if movmem and xor and incdec: retcolor = 0x6666FF
        if xormem and incdec: retcolor = 0x3333FF
        
        return stags+stagsdism, retcolor
        
    ################################################################################################
    
    def GetFuncTags(self, funcea):
        if not self.bsavedLoopsInitialized:
            self.AnalyzeLoopsAndSave()
        for e in self.savedFuncs:
            if e[0]==funcea:
                return e[1]
        return ""
        
    ################################################################################################
    
    def LoopsTagsToFunctions(self):
        self.savedFuncs = []
        for e in self.savedLoops:
            funcea = e[0]
            tags = e[3].split("   ///  ")[0].split(" ")
            bfound = False
            for i in range(0, len(self.savedFuncs)):
                if self.savedFuncs[i][0] == funcea:
                    bfound = True
                    for t in tags:
                        print(self.savedFuncs[i][1])
                        if t not in self.savedFuncs[i][1]: 
                            self.savedFuncs[i] = (self.savedFuncs[i][0], self.savedFuncs[i][1]+" "+t)
                    break
            if not bfound:
                stags = ""
                for e in tags: stags += (e + " ")
                self.savedFuncs.append((funcea, stags))
        for i in range(0, len(self.savedFuncs)):
            orderedtags = sorted(self.savedFuncs[i][1].split(" "))
            sorderedtags = ""
            for e in orderedtags: sorderedtags += (e + " ")
            self.savedFuncs[i] = (self.savedFuncs[i][0], sorderedtags)
            print(self.savedFuncs[i])
            
    ################################################################################################
    
    def AnalyzeLoopsAndSave(self):
        k = 1
        segs = []
        for e in IDAAPI_Segments():
            segs.append(e)
        lowerea = segs[0]
        upperea = IDAAPI_SegEnd(segs[-1])
        sys.stdout.write('Analyzing loops: *')
        for funcea in IDAAPI_Functions(lowerea, upperea):
            if 1:#if GetFunctionName(funcea) not in imp:
                loops = Utils.loopsInFunc(funcea)
                if loops:
                    for i in range(0, len(loops)):
                        loopend = loops[i][0]
                        loopstart = loops[i][1]
                        if i==len(loops)-1 or loops[i+1][1]!=loopstart or (loops[i+1][0]-loops[i+1][1]<loopend-loopstart):
                            if not k%100:
                                #print "Analyzing at %x len %x" % (loopstart, loopend-loopstart)
                                sys.stdout.write('*')
                            cmt = IDAAPI_CommentEx(IDAAPI_ItemHead(loopstart), 1)
                            if cmt==None: cmt=""
                            tags, loopcolor = AnalyzerLoops.FastAnalysisLoop(loopstart, loopend)
                            if tags!="": self.savedLoops.append((funcea, loopstart, loopend, tags, loopcolor))
                        k += 1
        self.savedLoops = sorted(self.savedLoops, cmp=self.cmpsavedloops)
        self.LoopsTagsToFunctions()
        self.bsavedLoopsInitialized = True

    def cmpsavedloops(self, a, b):
        if len(a[3]) < len(b[3]): return 1
        elif len(a[3]) > len(b[3]): return -1
        elif a[3] < b[3]: return 1
        else: return -1 

    ################################################################################################

    def AnalyzedLoopsToIdb(self, bColorizeLoops):
        self.gPrinter.doPrint("Suspicious loops:", "loops")
        self.gPrinter.doPrint("----------------------------------------------------------", "loops")
        if not self.bsavedLoopsInitialized:
            self.AnalyzeLoopsAndSave()
        for e in self.savedLoops:
            funcea = e[0]
            functionname = IDAAPI_GetFunctionName(funcea)
            loopstart = e[1]
            loopend = e[2]
            tags = e[3]
            loopcolor = e[4]
            cmt = IDAAPI_CommentEx(IDAAPI_ItemHead(loopstart), 1)
            if cmt==None: cmt=""
            if tags!="": 
                self.gPrinter.doPrint("%x - suspicious_loop(%s)(len=%x)(function= %s )" % (IDAAPI_ItemHead(loopstart), tags, loopend-loopstart, functionname), "loops")
            if tags!="" and tags not in cmt:
                IDAAPI_MakeRptCmt(IDAAPI_ItemHead(loopstart), "%s suspicious_loop(%s)(len=%x)(function= %s )" % (cmt, tags, loopend-loopstart, functionname))
                if bColorizeLoops and loopcolor: 
                    for looptempea in range(loopstart, loopend):
                        IDAAPI_SetColor(looptempea, CIC_ITEM, loopcolor)
        self.gPrinter.doPrint("----------------------------------------------------------", "loops")
        self.gPrinter.doPrint("", "loops")
        self.gPrinter.doPrint("", "loops")
