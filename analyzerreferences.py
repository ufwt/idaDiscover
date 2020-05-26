import sys
from ida_defines import *
from importlib import import_module

#format for renamed function: (fwd = function with description)  fwd@name1@depth1@name2@depth2...@nameN@depthN@fwd

class AnalyzerReferences():
    
        ################################################################################################

        def __init__(self, gPrinter, callTargets):
            self.gPrinter = gPrinter
            try:
                self.ahocorasickmod = import_module("py_aho_corasick.py_aho_corasick")
            except:
                self.ahocorasickmod = None
                print("Unable to import py_aho_corasick")
                return
            self.automaton = self.ahocorasickmod.Automaton(callTargets)
            
        ################################################################################################

        def AppendName(self, lnames, newname):
            for i in range(0, len(lnames)):
                if newname[0]==lnames[i][0]:
                    if newname[1]>lnames[i][1]:
                        del lnames[i]
                        break
                    else:
                        return lnames
            lnames.append(newname)
            return lnames

        ################################################################################################
        
        def SplitFwdNameAndAppendNames(self, lnames, name):
            name = name.split("fwd@")[1]
            name = name.split("@fwd")[0]
            l = name.split("@")
            for i in range(0, len(l)):
                lnames = self.AppendName(lnames, l[i])
            return lnames

        ################################################################################################
        
        def CompareUpNames(self, name1, name2):
            name1 = ''.join(sorted(self.SplitFwdNameAndAppendNames([], name1)))
            name2 = ''.join(sorted(self.SplitFwdNameAndAppendNames([], name2)))
            return name1 == name2

        ################################################################################################

        def AnalyzeUpNames(self):
            self.gPrinter.doPrint("Up Names:", "references")
            self.gPrinter.doPrint("----------------------------------------------------------", "references")
            if not self.ahocorasickmod:
                print("Ahocorasickmod was not loaded")
                return
            nAnalyzeUpNamesIter = 0
            bAtLeastOneFunctionRenamed = True
            nFuncRenamedLastIter = 0
            while bAtLeastOneFunctionRenamed:
                nAnalyzeUpNamesIter += 1
                bAtLeastOneFunctionRenamed = False
                nFuncRenamedLastIter = 0
                for segea in IDAAPI_Segments():
                    for funcea in IDAAPI_Functions(IDAAPI_SegStart(segea), IDAAPI_SegEnd(segea)):
                        lnames = []
                        #functionName = GetFunctionName(funcea)
                        #print "Current function: %s" % functionName
                        funcend = IDAAPI_GetFunctionAttr(funcea, IDAAPI_FUNCATTR_END)
                        for head in IDAAPI_Heads(funcea, funcend): 
                            dism = IDAAPI_GetDisasm(head)
                            if "fwd@" in dism and "@fwd" in dism:
                                lnames = self.SplitFwdNameAndAppendNames(lnames, dism)
                            else:
                                for indexfound, original_value, v in self.automaton.get_keywords_found(dism):
                                    lnames = self.AppendName(lnames, original_value)
                        if len(lnames):
                            funcname = "fwd@"
                            for name in lnames:
                                funcname += (name + "@")
                            funcname += "fwd"
                            curname = IDAAPI_GetFunctionName(funcea)
                            if "fwd@" not in curname or not self.CompareUpNames(curname, funcname):
                                for i in range(0, 10000):
                                    if IDAAPI_MakeNameEx(funcea, funcname+str(i), IDAAPI_SN_CHECK|IDAAPI_SN_NOWARN):
                                        bAtLeastOneFunctionRenamed = True
                                        nFuncRenamedLastIter += 1
                                        self.gPrinter.doPrint("%x - %s" % (funcea, funcname+str(i)), "references")
                                        break
            self.gPrinter.doPrint("----------------------------------------------------------", "references")
            self.gPrinter.doPrint("", "references")
            self.gPrinter.doPrint("", "references")

        ################################################################################################

        def ResetUpNames(self):
            for segea in IDAAPI_Segments():
                for funcea in IDAAPI_Functions(IDAAPI_SegStart(segea), IDAAPI_SegEnd(segea)):
                    curname = IDAAPI_GetFunctionName(funcea)
                    if "fwd@" in curname and "@fwd" in curname:
                        IDAAPI_MakeNameEx(funcea, "", IDAAPI_SN_CHECK|IDAAPI_SN_NOWARN)
        
        ################################################################################################
        
        def CreateFunctionsForUnreferencedCodeBlocks(self):
            funcs = []
            unreferencedcode = []
            for segea in IDAAPI_Segments():
                for funcea in IDAAPI_Functions(IDAAPI_SegStart(segea), IDAAPI_SegEnd(segea)):
                    funcend = IDAAPI_GetFunctionAttr(funcea, IDAAPI_FUNCATTR_END)
                    funcs.append((funcea, funcend))
            if len(funcs):
                for i in range(0, len(funcs)-1):
                    unreferencedcode.append((funcs[i][1], funcs[i+1][0]))
            for unref in unreferencedcode:
                print(hex(unref[0]).replace("L",""), hex(unref[1]).replace("L",""))
                ptrstart = unref[0]
                ptrend = unref[0]
                while ptrstart < unref[1]:
                    while not IDAAPI_IsCode(IDAAPI_GetFlags(ptrstart)) and ptrstart<unref[1]: ptrstart+=1
                    if ptrstart<unref[1]:
                        ptrend = ptrstart
                        while IDAAPI_IsCode(IDAAPI_GetFlags(ptrend)) and ptrend<unref[1]: ptrend+=1
                        if ptrend>ptrstart:
                            print("MakeFunction", hex(ptrstart), hex(ptrend))
                            IDAAPI_MakeFunction(ptrstart, ptrend)
                            ptrstart = ptrend
                        else:
                            break
                    else:
                        break
