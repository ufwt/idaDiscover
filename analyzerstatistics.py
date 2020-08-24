#
# idaDiscover plugin - by Javier Vicente Vallejo - @vallejocc
#

from ida_defines import *

class AnalyzerStatistic():
    
####################################################################################################

    ################################################################################################
    
    def __init__(self, gPrinter):
        self.gPrinter = gPrinter
        
    ################################################################################################
    
    def SearchMostUsedFunctions(self, nfuncs=0xffffffff, loopsAnalz=None):
        l = []
        #TODO: discard functions with a name already set?
        for ea in IDAAPI_Segments():
            for funcea in IDAAPI_Functions(IDAAPI_SegStart(ea), IDAAPI_SegEnd(ea)):
                refs = []
                for r in IDAAPI_XrefsTo(funcea, 0): refs.append(r)
                l.append((funcea, len(refs)))
        l = sorted(l, key=lambda l: l[1], reverse=True)
        i = 0
        self.gPrinter.doPrint("List of functions ordered by number of references:", "functions")
        self.gPrinter.doPrint("----------------------------------------------------------", "functions")
        while i<nfuncs and i<len(l):
            functags = loopsAnalz.GetFuncTags(l[i][0])
            self.gPrinter.doPrint("Function %x - references %x ( %s ) - ( %s )" % (l[i][0], l[i][1], IDAAPI_GetFunctionName(l[i][0]), functags), "functions")
            i += 1
        self.gPrinter.doPrint("----------------------------------------------------------", "functions")
        self.gPrinter.doPrint("", "functions")
        self.gPrinter.doPrint("", "functions")
