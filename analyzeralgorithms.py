from ida_defines import *
from utils import Utils

class AnalyzerAlgorithms():
    
    GEN_REG = 0x1           # General Register (al, ax, es, ds...) reg
    MEM_REF = 0x2           # Direct Memory Reference  (DATA)      addr
    BASE_INDEX = 0x3        # Memory Ref [Base Reg + Index Reg]    phrase
    BASE_INDEX_DISP = 0x4   # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
    IMMED = 0x5             # Immediate Value                      value
    FAR = 0x6               # Immediate Far Address  (CODE)        addr
    NEAR = 0x7              # Immediate Near Address (CODE)        addr

    ################################################################################################
    
    def isimm(self, t):
        if t==self.IMMED or t==self.FAR or t==self.NEAR: return 1
        return 0

    ################################################################################################
    
    def isreg(self, t):
        if t==self.GEN_REG: return 1
        return 0

    ################################################################################################
    
    def ismem(self, t):
        if t==self.MEM_REF or t==self.BASE_INDEX or t==self.BASE_INDEX_DISP: return 1
        return 0

    ################################################################################################
    
    def isnondirectmem(self, t):
        if t==self.BASE_INDEX or t==self.BASE_INDEX_DISP: return 1
        return 0

    ################################################################################################
    
    def __init__(self, gPrinter):
        self.gPrinter = gPrinter

    ################################################################################################

    def HeuristicIdentificationRc4(self):
        
        #http://blog.talosintelligence.com/2014/06/an-introduction-to-recognizing-and.html
        
        #SBox_Initialize Examples:
        #------------------------------
        #mov ebp, 100h
        #SBox_Initialize:
        #mov [edi], al
        #inc eax
        #inc edi
        #cmp ax, bp
        #jb short SBox_Initialize
        #------------------------------
        #sbox_initialize:
        #mov [eax+ecx], al
        #inc eax
        #cmp eax, 100h
        #jl short sbox_initialize
        #------------------------------
        
        #SBox_Scramble:
        #------------------------------
        #mov bl, [esi+ecx]             ; BL = S[i]
        #...
        #movzx eax, byte ptr [edx+eax] ; EAX = key[i mod keylen]
        #...
        #mov al, [edi+ecx]             ; AL = s[j]
        #...
        #mov [esi+ecx], al             ; S[i] = S[j]
        #...        
        #10002122 mov    [edi+ecx], bl
        #------------------------------
        
        l = []
        for ea in IDAAPI_Segments():
            for funcea in IDAAPI_Functions(IDAAPI_SegStart(ea), IDAAPI_SegEnd(ea)):
                functionName = IDAAPI_GetFunctionName(funcea)
                SBox_Scramble_addr = None
                SBox_Initialize_addr = None
                registers_moved_with_100h = []
                for (startea, endea) in IDAAPI_Chunks(funcea):
                    #collect registers where mov reg, 0x100
                    for head in IDAAPI_Heads(startea, endea):
                        ins = IDAAPI_GetMnem(head)
                        op0 = IDAAPI_GetOpType(head, 0)
                        op1 = IDAAPI_GetOpType(head, 1)
                        if ins=="mov" and self.isreg(op0) and self.isimm(op1) and IDAAPI_GetOperandValue(head,1)==0x100: 
                            v0 = IDAAPI_GetOperandValue(head,0)
                            if v0 not in registers_moved_with_100h: registers_moved_with_100h.append(v0)
                #lets try to find the SBox_Initialize and SBox_Scramble loop
                loops = Utils.loopsInFunc(funcea)
                if loops:
                    #check if SBox_Scramble loop exists in the function, by checking that it exists mov?? reg, [reg1+reg2] and a parallel instruction mov [reg1+reg2], reg for it
                    bCandidate_SBox_Scramble_Found = False
                    for loop in loops:
                        lop0=[]
                        lop1=[]
                        for head in IDAAPI_Heads(loop[1], loop[0]):
                            dism = IDAAPI_GetDisasm(head)
                            ins = IDAAPI_GetMnem(head)
                            op0 = IDAAPI_GetOpType(head, 0)
                            op1 = IDAAPI_GetOpType(head, 1)
                            if ins=="mov":
                                #log operand1 for each mov?? reg, [reg1+reg2] instruction
                                if op1==self.BASE_INDEX:
                                   opnd=Utils.GetOperandsTxtFromInsTxt(dism)[1]
                                   if opnd and "+" in opnd and opnd not in lop1: 
                                       lop1.append(opnd)
                                #log operand0 for each mov?? [reg1+reg2], reg instruction
                                if op0==self.BASE_INDEX:
                                   opnd=Utils.GetOperandsTxtFromInsTxt(dism)[0]
                                   if opnd and "+" in opnd and opnd not in lop0:
                                       lop0.append(opnd)
                        #once operands are logged for each mov?? reg,[reg1+reg2] or mov?? [reg1+reg2] instructions, lets check if there are "parallel" instructions
                        for e in lop0:
                            if e in lop1: 
                                bCandidate_SBox_Scramble_Found = True
                                SBox_Scramble_addr = loop[1]
                                break
                        if bCandidate_SBox_Scramble_Found:
                            break
                    #check if SBox_initialize loop exists in the function
                    for loop in loops:
                        #it should be a short loop (40 bytes>looplen has been choosen, maybe necesary to change)
                        if loop[0]-loop[1]<40:
                            #collect diferent parameters for the loop
                            cmp_with_100h = 0
                            cmp_with_reg_moved_with_100h = 0
                            inc_reg = 0
                            mov_mem_reg = 0
                            for head in IDAAPI_Heads(loop[1], loop[0]):
                                ins = IDAAPI_GetMnem(head)
                                op0 = IDAAPI_GetOpType(head, 0)
                                op1 = IDAAPI_GetOpType(head, 1)
                                #contabilize: cmp ???, 100h
                                if ins=="cmp" and \
                                   self.isimm(op1) and \
                                   IDAAPI_GetOperandValue(head,1)==0x100: 
                                    cmp_with_100h+=1
                                #contabilize: cmp ???, reg (previously moved with 100h)
                                if ins=="cmp" and \
                                   self.isreg(op0) and \
                                   self.isreg(op1) and \
                                   IDAAPI_GetOperandValue(head,1) in registers_moved_with_100h: 
                                    cmp_with_reg_moved_with_100h+=1
                                #contabilize: inc reg
                                if ins=="inc" and \
                                   self.isreg(op0):
                                    inc_reg+=1
                                #contabilize: mov [mem], reg
                                if ins=="mov" and \
                                   self.isnondirectmem(op0) and \
                                   self.isreg(op1):
                                    mov_mem_reg+=1
                            #check some conditions typicals of the SBox_initialize loop
                            if (inc_reg>0 and inc_reg<4) and \
                               (cmp_with_100h==1 or cmp_with_reg_moved_with_100h==1) and \
                                mov_mem_reg==1:
                                SBox_Initialize_addr = loop[1]
                                if bCandidate_SBox_Scramble_Found:
                                    IDAAPI_MakeRptCmt(SBox_Initialize_addr, "SBox_initialize")
                                    IDAAPI_MakeRptCmt(SBox_Scramble_addr, "SBox_Scramble")
                                    IDAAPI_MakeRptCmt(funcea, "Heuristic: candidate rc4 SBox_initialize and SBox_Scramble found")
                                    self.gPrinter.doPrint("%s - candidate rc4 SBox_initialize and SBox_Scramble found" % functionName, "algorithms")
                                    l.append(funcea)
                                else:
                                    self.gPrinter.doPrint("%s - candidate rc4 SBox_initialize found but SBox_Scramble not found" % functionName, "algorithms")
                                    #IDAAPI_MakeRptCmt(funcea, "Heuristic: candidate rc4 SBox_initialize found but SBox_Scramble not found")
        return l

    ################################################################################################

    def HeuristicIdentificationAlgorithms(self):
        l = []
        self.gPrinter.doPrint("Heuristic identification algorithms results:", "algorithms")
        self.gPrinter.doPrint("----------------------------------------------------------", "algorithms")
        l += self.HeuristicIdentificationRc4()
        self.gPrinter.doPrint("----------------------------------------------------------", "algorithms")
        self.gPrinter.doPrint("", "algorithms")
        self.gPrinter.doPrint("", "algorithms")
        return l
