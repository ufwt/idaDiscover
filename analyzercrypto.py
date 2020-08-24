#
# idaDiscover plugin - by Javier Vicente Vallejo - @vallejocc
#

from ida_defines import *
from importlib import import_module
from utils import Utils
import hashlib
from aes import AESModeOfOperationCBC
from aes import AESModeOfOperationECB
import binascii

class AnalyzerCrypto():
    
    ################################################################################################
    
    def __init__(self, gPrinter, apiNameCrcs):
        self.savedStackStringsPieces = []
        self.allThePieces = []
        self.gPrinter = gPrinter
        self.RevealPE = None
        self.ahocorasickmod = None
        try:
            self.ahocorasickmod = import_module("py_aho_corasick.py_aho_corasick")
        except:
            self.ahocorasickmod = None
            print("Unable to import py_aho_corasick")
            return
        try:
            self.RevealPE = import_module("RevealPE.revealpe")
        except:
            print("Error importing RevealPE. Please execute installation")
            return
        self.apiNames = []
        self.apiCrcs = []
        for e in apiNameCrcs: 
            self.apiCrcs.append(e[1])
            self.apiNames.append(e[0])
        self.automatonApiCrcs = self.ahocorasickmod.Automaton(self.apiCrcs)

    ################################################################################################

    def SearchEncryptedTextsToIdb(self, encryptedTxtsToSearch):
        if not self.RevealPE:
            self.RevealPE = import_module("RevealPE.revealpe")
        if self.RevealPE:
            self.gPrinter.doPrint("Search encrypted texts results:", "crypto")
            self.gPrinter.doPrint("----------------------------------------------------------", "crypto")
            for ea in Segments():
                content = IDAAPI_GetManyBytes(IDAAPI_SegStart(ea), IDAAPI_SegEnd(ea)-IDAAPI_SegStart(ea))
                lpes, ldeccontents = self.RevealPE.doWorkPESearch(content)
                for e in ldeccontents:
                    pos = e[1] 
                    alg = e[2] 
                    key = e[3]
                    inc = e[4]
                    addr = IDAAPI_SegStart(ea)+e[1]
                    IDAAPI_MakeRptCmt(IDAAPI_ItemHead(addr), "Encrypted PE found pos: %x alg: %s key: %x inc: %x" % (addr, alg, key, inc))
                    self.gPrinter.doPrint("Encrypted PE found pos: %x alg: %s key: %x inc: %x" % (addr, alg, key, inc), "crypto")
                                    
            for enctxt in encryptedTxtsToSearch:
                print("Searching for encrypted text %s" % enctxt)
                for ea in IDAAPI_Segments():
                    content = IDAAPI_GetManyBytes(IDAAPI_SegStart(ea), IDAAPI_SegEnd(ea)-IDAAPI_SegStart(ea))
                    l = self.RevealPE.doWorkRawSearch(content, Utils.UnescapeSeqHexa(enctxt))
                    for e in l:
                        pos = e[1] 
                        alg = e[2] 
                        key = e[3]
                        inc = e[4]
                        addr = IDAAPI_SegStart(ea)+e[1]
                        IDAAPI_MakeRptCmt(IDAAPI_ItemHead(addr), "Encrypted text found: %s pos: %x alg: %s key: %x inc: %x" % (enctxt, addr, alg, key, inc))
                        self.gPrinter.doPrint("Encrypted text found: %s pos: %x alg: %s key: %x inc: %x" % (enctxt, addr, alg, key, inc), "crypto")
            self.gPrinter.doPrint("----------------------------------------------------------", "crypto")
            self.gPrinter.doPrint("", "crypto")
            self.gPrinter.doPrint("", "crypto")
        else:
            print("RevealPE was not imported. Aborting search encrypted texts")

    ################################################################################################
    
    def IsValidText(self, s):
        for e in s:
            e = ord(e)
            if e>126: return False
            if e<32 and not (e==9 or e==0xa or e==0xd): return False
        return True
    
    ################################################################################################
    
    def Wide2Ascii(self, s):
        sout = ""
        if not len(s)%2:
            for i in range(0, len(s)/2):
                if ord(s[1+2*i]): return s, False
                sout += s[2*i]
        return sout, True

    ################################################################################################
    
    def SearchStackStringsInFunctionHeadsList32(self, lheads, funcea, bignoretrash=False):
        functionName = IDAAPI_GetFunctionName(funcea)
        curpieces = []
        for head in lheads:
            dism = IDAAPI_GetDisasm(head)
            bnewpiece = False
            curtxt = None
            sz = -1
            bvalidtxt = False
            bmov2stack = False
            bimm2stack = False
            bwide = False
            dism = dism.split(";")[0] #remove comments
            if "mov     dword ptr [ebp" in dism or "mov     word ptr [ebp" in dism or "mov     byte ptr [ebp" in dism or "mov     [ebp+" in dism:
                bmov2stack = True
                op1 = IDAAPI_GetOpType(head, 1)
                if op1==5 or op1==6 or op1==7:
                    bimm2stack = True
                    v = IDAAPI_GetOperandValue(head, 1)
                    if ("mov     dword ptr [ebp" in dism) or ("mov     [ebp+" in dism):
                        curtxt = chr(v&0xff) + chr((v&0xff00)>>8) + chr((v&0xff0000)>>16) + chr((v&0xff000000)>>24)
                        sz = 4
                    elif ("mov     word ptr [ebp" in dism):
                        curtxt = chr(v&0xff) + chr((v&0xff00)>>8)
                        sz = 2
                    elif ("mov     byte ptr [ebp" in dism):
                        curtxt = chr(v)
                        sz = 1
                    if curtxt: 
                        curtxt, bwide = self.Wide2Ascii(curtxt)
                        sz = len(curtxt)
                    if self.IsValidText(curtxt):
                        IDAAPI_MakeRptCmt(head, curtxt)
                        print("%x: stack piece: %s" % (head, curtxt))
                        bvalidtxt = True
                        if not len(curpieces): bnewpiece = True #first piece, accept it always
                        elif bwide and curpieces[-1][3] and sz==2 and curpieces[-1][2]==2: bnewpiece = True
                        elif bwide and curpieces[-1][3] and sz==1 and curpieces[-1][2]==2: bnewpiece = True
                        elif bwide and curpieces[-1][3] and sz==1 and curpieces[-1][2]==1: 
                            if len(curpieces)==1: bnewpiece = True #until now, two "mov byte [x],y" have been seen
                            elif curpieces[-2][2]==1: bnewpiece = True #until new only "mov byte [x],y" have been seen, we accept one more            
                        elif not bwide and not curpieces[-1][3] and sz==4 and curpieces[-1][2]==4: bnewpiece = True #continuation "mov dword [x],y" piece
                        elif not bwide and not curpieces[-1][3] and sz==2 and curpieces[-1][2]==4: bnewpiece = True #if len(str)%4 != 0, we could find "mov word [x],y" or "mov byte [x],y" after multiple "mov dword [x],y"
                        elif not bwide and not curpieces[-1][3] and sz==1 and curpieces[-1][2]==4: bnewpiece = True 
                        elif not bwide and not curpieces[-1][3] and sz==1 and curpieces[-1][2]==2: bnewpiece = True #if len(str)%4 == 3, we could find multiple "mov dword [x],y", followed by one "mov word [x],y" and one "mov byte [x],y"
                        elif not bwide and not curpieces[-1][3] and sz==1 and curpieces[-1][2]==1: #if we find two followed "mov byte [x],y", we will only accept "mov byte [x],y" pieces and we must do some additional checks
                            if len(curpieces)==1: bnewpiece = True #until now, two "mov byte [x],y" have been seen
                            elif curpieces[-2][2]==1: bnewpiece = True #until new only "mov byte [x],y" have been seen, we accept one more            
            #ignore current ins if ignoretrash is activated and its an instruction that is not modifying stack (mov ??? ptr [ebp+???], ???)
            if bignoretrash and not bmov2stack:
                pass #print "ignore trash", hex(funcea), dism, curtxt
            elif bnewpiece: 
                #print "new piece", hex(funcea), dism, curtxt
                curpieces.append((head, curtxt, sz, bwide)) #add a new piece to the current string
                self.allThePieces.append((head, curtxt, sz, bwide))
            else: 
                #print "closing curpieces with length", len(curpieces), hex(funcea), dism, curtxt
                self.savedStackStringsPieces.append((functionName, curpieces)) #no more pieces for the current string, append string to the list
                if bvalidtxt: curpieces = [(head, curtxt, sz)] #if we have closed the current string but we had a new possible beggining of string, start with it the new set of pieces
                else: curpieces = []
        
    ################################################################################################
    
    def SearchStackStringsPermutedCode(self):
        self.savedStackStringsPieces = []
        self.allThePieces = []
        for segea in IDAAPI_Segments():
            for funcea in IDAAPI_Functions(IDAAPI_SegStart(segea), IDAAPI_SegEnd(segea)):
                lheads = []
                #functionName = GetFunctionName(funcea)
                #print "Current function: %s" % functionName
                f = IDAAPI_get_func(funcea)
                fc = IDAAPI_FlowChart(f)
                lblocks = []
                for block in fc:
                    lblocks.append(block)
                lorderedblocks = []
                while len(lblocks):
                    first = lblocks.pop(0)
                    lorderedblocks.append(first)
                    for head in IDAAPI_Heads(first.startEA, first.endEA):
                        ins = IDAAPI_GetMnem(head)
                        #search any jump in the current bblock, and search the target bblock of the jump
                        #then, insert each bblock into the beginning of the lblocks array (in this way
                        #we will analyze all the bblocks like a "tree", in the order that bblocks are referenced
                        if len(ins) and ins[0]=='j':
                            op0 = IDAAPI_GetOpType(head, 0)
                            if op0==5 or op0==6 or op0==7:
                                v = IDAAPI_GetOperandValue(head, 0)
                                for i in range(0, len(lblocks)):
                                    if v == lblocks[i].startEA: 
                                        #print "Moving block %x:%x" % (head, v)
                                        lblocks.insert(0, lblocks.pop(i))
                                        break
                for block in lorderedblocks:
                    for head in IDAAPI_Heads(block.startEA, block.endEA):
                        lheads.append(head)
                self.SearchStackStringsInFunctionHeadsList32(lheads, funcea, bignoretrash = True)

    ################################################################################################
    
    def SearchStackStringsNotPermutedCode(self):
        self.savedStackStringsPieces = []
        self.allThePieces = []
        for segea in IDAAPI_Segments():
            for funcea in IDAAPI_Functions(IDAAPI_SegStart(segea), IDAAPI_SegEnd(segea)):
                lheads = []
                #functionName = GetFunctionName(funcea)
                #print "Current function: %s" % functionName
                funcend = IDAAPI_GetFunctionAttr(funcea, IDAAPI_FUNCATTR_END)
                for head in IDAAPI_Heads(funcea, funcend): 
                    lheads.append(head)
                self.SearchStackStringsInFunctionHeadsList32(lheads, funcea, bignoretrash = False)

    ################################################################################################
    
    def SearchStackStringsToIdb(self, bPermutedCode = False):
        if bPermutedCode: self.SearchStackStringsPermutedCode()
        else: self.SearchStackStringsNotPermutedCode()
        self.gPrinter.doPrint("Strings constructed in stack:", "crypto")
        self.gPrinter.doPrint("----------------------------------------------------------", "crypto")
        for curStackStringsPieces in self.savedStackStringsPieces:
            functionName = curStackStringsPieces[0]
            curpieces = curStackStringsPieces[1]
            piecefulltxt = ""
            for piece in curpieces: piecefulltxt += piece[1]
            if len(piecefulltxt)>6: #we only accept strings constructed in stack longer than 6 bytes
                begginingstringea = curpieces[0][0]
                for piece in curpieces: IDAAPI_MakeRptCmt(piece[0], piece[1]) #set comments in the code with the text of each piece
                self.gPrinter.doPrint("%s - %x - %s" % (functionName, begginingstringea, piecefulltxt), "crypto")
        self.gPrinter.doPrint("----------------------------------------------------------", "crypto")
        self.gPrinter.doPrint("", "crypto")
        self.gPrinter.doPrint("", "crypto")
        self.gPrinter.doPrint("All the candidate pieces for strings constructed in stack:", "crypto")
        self.gPrinter.doPrint("----------------------------------------------------------", "crypto")
        for singlePiece in self.allThePieces:
            widechar = ""
            if singlePiece[3]: widechar = "(widechar)"
            self.gPrinter.doPrint("%x - %s %s" % (singlePiece[0], singlePiece[1], widechar), "crypto")
        self.gPrinter.doPrint("----------------------------------------------------------", "crypto")
        self.gPrinter.doPrint("", "crypto")
        self.gPrinter.doPrint("", "crypto")

    ################################################################################################
    
    def SearchApiCrc32UsageToIdb(self):
        self.gPrinter.doPrint("Apis crc32 found:", "crypto")
        self.gPrinter.doPrint("----------------------------------------------------------", "crypto")
        for segea in IDAAPI_Segments():
            for funcea in IDAAPI_Functions(IDAAPI_SegStart(segea), IDAAPI_SegEnd(segea)):
                funcend = IDAAPI_GetFunctionAttr(funcea, IDAAPI_FUNCATTR_END)
                for head in IDAAPI_Heads(funcea, funcend):
                    dism = IDAAPI_GetDisasm(head)
                    for indexfound, original_value, v in self.automatonApiCrcs.get_keywords_found(dism):
                        bin_i, bin_found  = Utils.BinarySearch(self.apiCrcs, original_value)
                        if bin_found: 
                            IDAAPI_MakeRptCmt(head, self.apiNames[bin_i])
                            self.gPrinter.doPrint("%x - %s - %s" % (head, self.apiCrcs[bin_i], self.apiNames[bin_i]), "crypto")
                            break
        self.gPrinter.doPrint("----------------------------------------------------------", "crypto")
        self.gPrinter.doPrint("", "crypto")
        self.gPrinter.doPrint("", "crypto")

    ################################################################################################
    
    def RC4(self, data, key):
        x = 0
        box = range(256)
        for i in range(256):
            x = (x + box[i] + ord(key[i % len(key)])) % 256        
            box[i], box[x] = box[x], box[i]
        x = 0
        y = 0
        out = []
        for char in data:
            x = (x + 1) % 256
            y = (y + box[x]) % 256
            box[x], box[y] = box[y], box[x]
            out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))
        return ''.join(out)

    ################################################################################################
    
    def AESCbcDecrypt(self, data, aeskey, aesiv):
        data += ((0x10-(len(data)%0x10))*" ")
        data = Utils.Chunks(data, 16)
        aeswork = AESModeOfOperationCBC(aeskey, iv = aesiv)
        return ''.join([aeswork.decrypt(d) for d in data])

    ################################################################################################
    
    def AESEcbDecrypt(self, data, aeskey, aesiv):
        data += ((0x10-(len(data)%0x10))*" ")
        data = Utils.Chunks(data, 16)
        aeswork = AESModeOfOperationECB(aeskey) #, iv = aesiv)
        return ''.join([aeswork.decrypt(d) for d in data])
    
    ################################################################################################
    
    def sha256(self, data):
        m = hashlib.sha256()
        m.update(data)
        return m.digest()

    ################################################################################################
    
    def md5(self, data):
        m = hashlib.md5()
        m.update(data)
        return m.digest()

    ################################################################################################
    
    def xor(self, data, key):
        out=""
        j=0
        for i in range(0, len(data)):
            out += chr(ord(data[i])^ord(key[j]))
            j+=1
            if j>=len(key):j=0
        return out

    ################################################################################################

    def SearchEncryptedRc4(self, selectedContent1, selectedKey1, selectedSearchBlockSize1, selectedStringFromMenu):
        res = []
        if len(selectedContent1) and selectedSearchBlockSize1>0 and len(selectedStringFromMenu):
            blksz = selectedSearchBlockSize1
            if len(selectedContent1)<=blksz: 
                blksz = len(selectedContent1)-1
            for i in range(0, len(selectedContent1)-blksz):
                dec = self.RC4(selectedContent1[i:i+blksz], selectedKey1)
                if selectedStringFromMenu in dec:
                    res.append(i)
        return res

    ################################################################################################

    def SearchEncryptedAes(self, selectedContent1, selectedKey1, selectedKey2, selectedSearchBlockSize1, selectedStringFromMenu, bEcb):
        res = []
        if len(selectedContent1) and selectedSearchBlockSize1>0 and len(selectedStringFromMenu):
            blksz = selectedSearchBlockSize1
            if len(selectedContent1)<=blksz: 
                blksz = len(selectedContent1)-1
            for i in range(0, len(selectedContent1)-blksz):
                if not bEcb:
                    dec = self.AESCbcDecrypt(selectedContent1[i:i+blksz], selectedKey1, selectedKey2)
                else:
                    dec = self.AESEcbDecrypt(selectedContent1[i:i+blksz], selectedKey1, selectedKey2)
                if selectedStringFromMenu in dec:
                    res.append(i)
        return res

    ################################################################################################

    def SearchEncryptedXor(self, selectedContent1, selectedKey1, selectedSearchBlockSize1, selectedStringFromMenu):
        res = []
        if len(selectedContent1) and selectedSearchBlockSize1>0 and len(selectedStringFromMenu):
            blksz = selectedSearchBlockSize1
            if len(selectedContent1)<=blksz: 
                blksz = len(selectedContent1)-1
            for i in range(0, len(selectedContent1)-blksz):
                dec = self.xor(selectedContent1[i:i+blksz], selectedKey1)
                if selectedStringFromMenu in dec:
                    res.append(i)
        return res

    ################################################################################################
    
    def DoCryptoSimple(self, alg, content1, key1, key2, savepath=None):
        if alg == "RC4":
            Utils.ShowDataAndAskSave("RC4", self.RC4(content1, key1), savepath)
        elif alg == "AES CBC":
            Utils.ShowDataAndAskSave("AES CBC", self.AESCbcDecrypt(content1, key1, key2), savepath)
        elif alg == "AES ECB":
            Utils.ShowDataAndAskSave("AES ECB", self.AESEcbDecrypt(content1, key1, key2), savepath)
        elif alg == "XOR":
            Utils.ShowDataAndAskSave("XOR", self.xor(content1, key1), savepath)
        elif alg == "MD5":
            Utils.ShowDataAndAskSave("MD5", self.md5(content1), savepath)
        elif alg == "SHA256":
            Utils.ShowDataAndAskSave("SHA256", self.sha256(content1), savepath)

    ################################################################################################

    def DoCryptoWildcards(self, alg, content1, key1, key2):
        #check enabled wildcards
        IDANAMESCONTENT1 = [None]
        IDANAMESCONTENT2 = [None]
        IDANAMESCONTENT3 = [None]
        IMMOPERANDS1 = [None]
        IMMOPERANDS2 = [None]
        IMMOPERANDS3 = [None]
        for v in [content1, key1, key2]:
            if type(v) is str:
                if len(IDANAMESCONTENT1)==1 and IDANAMESCONTENT1[0]==None and "%IDANAMESCONTENT1%" in v:
                    sz = int(v.split("%IDANAMESCONTENT1%")[1].split("%")[0])
                    IDANAMESCONTENT1 = Utils.GetIDANamesContentsList(sz, bNoCode=True)
                if len(IDANAMESCONTENT2)==1 and IDANAMESCONTENT2[0]==None and "%IDANAMESCONTENT2%" in v:
                    sz = int(v.split("%IDANAMESCONTENT2%")[1].split("%")[0])
                    IDANAMESCONTENT2 = Utils.GetIDANamesContentsList(sz, bNoCode=True)
                if len(IDANAMESCONTENT3)==1 and IDANAMESCONTENT3[0]==None and "%IDANAMESCONTENT3%" in v:
                    sz = int(v.split("%IDANAMESCONTENT3%")[1].split("%")[0])
                    IDANAMESCONTENT3 = Utils.GetIDANamesContentsList(sz, bNoCode=True)
                if len(IMMOPERANDS1)==1 and IMMOPERANDS1[0]==None and "%IMMOPERANDS1%" in v:
                    IMMOPERANDS1 = Utils.GetInstructionsImmOperandsList()
                if len(IMMOPERANDS2)==1 and IMMOPERANDS2[0]==None and "%IMMOPERANDS2%" in v:
                    IMMOPERANDS2 = Utils.GetInstructionsImmOperandsList()
                if len(IMMOPERANDS3)==1 and IMMOPERANDS3[0]==None and "%IMMOPERANDS3%" in v:
                    IMMOPERANDS3 = Utils.GetInstructionsImmOperandsList()
        outputdir = Utils.AskDirectory("\r\n\r\n- Crypto - Please, enter the path of the output directory - \r\n\r\n")
        #foreach enabled wildward, replace wildcard for value
        for idanamescontent1 in IDANAMESCONTENT1:
            for idanamescontent2 in IDANAMESCONTENT2:
                for idanamescontent3 in IDANAMESCONTENT3:
                    for immoperands1 in IMMOPERANDS1:
                        for immoperands2 in IMMOPERANDS2:
                            for immoperands3 in IMMOPERANDS3:
                                internalcontent1 = content1
                                internalkey1 = key1
                                internalkey2 = key2
                                outputfile = "dec"
                                #generate internal parameters
                                if "%IDANAMESCONTENT1%" in content1: internalcontent1 = idanamescontent1["content"]
                                if "%IDANAMESCONTENT2%" in content1: internalcontent1 = idanamescontent2["content"]
                                if "%IDANAMESCONTENT3%" in content1: internalcontent1 = idanamescontent3["content"]
                                if "%IMMOPERANDS1%" in content1: internalcontent1 = struct.pack("<L", immoperands1&0xffffffff)
                                if "%IMMOPERANDS2%" in content1: internalcontent1 = struct.pack("<L", immoperands2&0xffffffff)
                                if "%IMMOPERANDS3%" in content1: internalcontent1 = struct.pack("<L", immoperands3&0xffffffff)
                                if "%IDANAMESCONTENT1%" in key1: internalkey1 = idanamescontent1["content"]
                                if "%IDANAMESCONTENT2%" in key1: internalkey1 = idanamescontent2["content"]
                                if "%IDANAMESCONTENT3%" in key1: internalkey1 = idanamescontent3["content"]
                                if "%IMMOPERANDS1%" in key1: internalkey1 = struct.pack("<L", immoperands1&0xffffffff)
                                if "%IMMOPERANDS2%" in key1: internalkey1 = struct.pack("<L", immoperands2&0xffffffff)
                                if "%IMMOPERANDS3%" in key1: internalkey1 = struct.pack("<L", immoperands3&0xffffffff)
                                if "%IDANAMESCONTENT1%" in key2: internalkey2 = idanamescontent1["content"]
                                if "%IDANAMESCONTENT2%" in key2: internalkey2 = idanamescontent2["content"]
                                if "%IDANAMESCONTENT3%" in key2: internalkey2 = idanamescontent3["content"]
                                if "%IMMOPERANDS1%" in key2: internalkey2 = struct.pack("<L", immoperands1&0xffffffff)
                                if "%IMMOPERANDS2%" in key2: internalkey2 = struct.pack("<L", immoperands2&0xffffffff)
                                if "%IMMOPERANDS3%" in key2: internalkey2 = struct.pack("<L", immoperands3&0xffffffff)
                                #generate outputfile name
                                if "%IDANAMESCONTENT1%" in content1: outputfile += "_content1_%s_%s" % (idanamescontent1["addr"], idanamescontent1["sz"])
                                if "%IDANAMESCONTENT2%" in content1: outputfile += "_content1_%s_%s" % (idanamescontent2["addr"], idanamescontent2["sz"])
                                if "%IDANAMESCONTENT3%" in content1: outputfile += "_content1_%s_%s" % (idanamescontent3["addr"], idanamescontent3["sz"])
                                if "%IMMOPERANDS1%" in content1: outputfile += "_content1_%s" % binascii.hexlify(struct.pack("<L", immoperands1&0xffffffff))
                                if "%IMMOPERANDS2%" in content1: outputfile += "_content1_%s" % binascii.hexlify(struct.pack("<L", immoperands2&0xffffffff))
                                if "%IMMOPERANDS3%" in content1: outputfile += "_content1_%s" % binascii.hexlify(struct.pack("<L", immoperands3&0xffffffff))
                                if "%IDANAMESCONTENT1%" in key1: outputfile += "_key1_%s_%s" % (idanamescontent1["addr"], idanamescontent1["sz"])
                                if "%IDANAMESCONTENT2%" in key1: outputfile += "_key1_%s_%s" % (idanamescontent2["addr"], idanamescontent2["sz"])
                                if "%IDANAMESCONTENT3%" in key1: outputfile += "_key1_%s_%s" % (idanamescontent3["addr"], idanamescontent3["sz"])
                                if "%IMMOPERANDS1%" in key1: outputfile += "_key1_%s" % binascii.hexlify(struct.pack("<L", immoperands1&0xffffffff))
                                if "%IMMOPERANDS2%" in key1: outputfile += "_key1_%s" % binascii.hexlify(struct.pack("<L", immoperands2&0xffffffff))
                                if "%IMMOPERANDS3%" in key1: outputfile += "_key1_%s" % binascii.hexlify(struct.pack("<L", immoperands3&0xffffffff))
                                if "%IDANAMESCONTENT1%" in key2: outputfile += "_key2_%s_%s" % (idanamescontent1["addr"], idanamescontent1["sz"])
                                if "%IDANAMESCONTENT2%" in key2: outputfile += "_key2_%s_%s" % (idanamescontent2["addr"], idanamescontent2["sz"])
                                if "%IDANAMESCONTENT3%" in key2: outputfile += "_key2_%s_%s" % (idanamescontent3["addr"], idanamescontent3["sz"])
                                if "%IMMOPERANDS1%" in key2: outputfile += "_key2_%s" % binascii.hexlify(struct.pack("<L", immoperands1&0xffffffff))
                                if "%IMMOPERANDS2%" in key2: outputfile += "_key2_%s" % binascii.hexlify(struct.pack("<L", immoperands2&0xffffffff))
                                if "%IMMOPERANDS3%" in key2: outputfile += "_key2_%s" % binascii.hexlify(struct.pack("<L", immoperands3&0xffffffff))
                                outputfile += ".bin"
                                #do simple crypto with replaced params
                                self.DoCryptoSimple(alg, internalcontent1, internalkey1, internalkey2, outputdir + "/" + outputfile)

    ################################################################################################

    def DoCrypto(self, alg, content1, key1, key2):
        wilds = ["%IDANAMESCONTENT1%", "%IDANAMESCONTENT2%", "%IDANAMESCONTENT3%", "%IMMOPERANDS1%", "%IMMOPERANDS2%", "%IMMOPERANDS3%"]
        params = [content1, key1, key2]
        for wild in wilds:
            for param in params:
                if wild in param:
                    return self.DoCryptoWildcards(alg, content1, key1, key2)
        return self.DoCryptoSimple(alg, content1, key1, key2)








