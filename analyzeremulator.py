#
# idaDiscover plugin - by Javier Vicente Vallejo - @vallejocc
#

from ida_defines import *
from importlib import import_module
from utils import Utils
import binascii
#from capstone import *
#from unicorn import *
#from unicorn.x86_const import *

def do_mem_map(mu, addr, size):
    addr2 = addr+size
    if addr&0xfff: addr1 = addr&0xfffff000
    else: addr1 = addr
    if addr2&0xfff: addr2 = (addr2&0xfffff000)+0x1000
    print("trying do_mem_map %x -> %x" % (addr1, addr2))
    while addr1<addr2:
        try:
            mu.mem_map(addr1, addr2-addr1)
            break
        except:
            print("error mapping!")
            print("trying do_mem_map %x -> %x" % (addr1, addr2))
            addr1 += 0x1000


def hook_mem_invalid(uc, access, address, size, value, user_data):
    if access==user_data.unicornmod.UC_MEM_WRITE_UNMAPPED or access==user_data.unicornmod.UC_MEM_READ_UNMAPPED:
        if user_data.debug: print(">>> Missing memory is being accessed at 0x%x, data size = %x" % (address, size))
        # map this memory in with the accessed size or 50kb if the accessed size is lower
        if size<50*1024: size=50*1024
        do_mem_map(uc, address, size)
        return True # return True to indicate we want to continue emulation
    else:
        return False # return False to indicate we want to stop emulation


def hook_mem_access(uc, access, address, size, value, user_data):
    if access == user_data.unicornmod.UC_MEM_WRITE:
        if user_data.debug: print(">>> Memory is being WRITE at 0x%x, data size = %u, data value = %x (%s) (%s)" % (address, size, value, repr(value), type(value)))
        if size==1:
            try: value = struct.pack("B", value)
            except: value = struct.pack("b", value)
        if size==2:
            try: value = struct.pack("<H", value)
            except: value = struct.pack("<h", value)
        if size==4:
            try: value = struct.pack("<L", value)
            except: value = struct.pack("<l", value)
        if size==8:
            try: value = struct.pack("<Q", value)
            except: value = struct.pack("<q", value)
        try: user_data.memwritten[address].append(value)
        except: user_data.memwritten[address] = [value]
        user_data.cronomemwritten.append((address, value))
    else: # READ
        pass


def hook_code(uc, address, size, user_data):
    user_data.count += 1
    if user_data.count == user_data.maxcount: 
        uc.emu_stop()
        return
    if user_data.debug or len(user_data.instoskip.items()):
        mem = str(uc.mem_read(address, size))
        disstr=""
        for (x, y, mnemonic, op_str) in user_data.caps.disasm_lite(mem, len(mem)):
            disstr = mnemonic+" "+op_str
            break
        if user_data.debug:
            print(">>> Tracing ins addr 0x%x, sz = 0x%x, %s" %(address, size, disstr))
            #eflags = uc.reg_read(UC_X86_REG_EFLAGS)
            #print(">>> --- EFLAGS is 0x%x" %eflags)
        for k, v in user_data.instoskip.items():
            if len(disstr)>=len(k) and k.lower()==disstr[0:len(k)].lower():
                #skip instructions
                if user_data.debug: print(">>> Skipping ins addr 0x%x, sz = 0x%x, %s" %(address, size, disstr))
                uc.reg_write(user_data.unicornctemod.UC_X86_REG_EIP, address+size)
                break


class AnalyzerEmulatorHooksSession():
    def __init__(self, analyzerEmulator):
        self.capstonemod = import_module("capstone")
        self.unicornmod = import_module("unicorn")
        self.unicornctemod = import_module("unicorn.x86_const")
        self.count = 0
        self.maxcount = 1000
        self.debug = 0
        self.memwritten = {}
        self.cronomemwritten = []
        self.instoskip = {}
        self.analyzerEmulator = analyzerEmulator
        self.caps = self.capstonemod.Cs(self.capstonemod.CS_ARCH_X86, self.capstonemod.CS_MODE_32)


class AnalyzerEmulator():
    
    ################################################################################################

    def __init__(self, gPrinter):
        self.gPrinter = gPrinter

    ################################################################################################

    def getStackMemRegs(self, addr):
        return {addr: "\x00"*0x200000}, {"ESP": addr, "EBP": addr+0x100000}

    ################################################################################################
    
    def mapCodeDataFromIDA(self, mu, fromaddr, toaddr, mapfullcode):
        if mapfullcode:
            for segea in IDAAPI_Segments():
                segstart = IDAAPI_SegStart(segea)
                segend = IDAAPI_SegEnd(segea)
                segcontent = IDAAPI_GetManyBytes(segstart, segend-segstart)
                print("mapping segment %x -> %x (len %x)" % (segstart, segend, len(segcontent)))
                do_mem_map(mu, segstart, len(segcontent))
                mu.mem_write(segstart, segcontent)
        else:
            if fromaddr<toaddr:
                blk = IDAAPI_GetManyBytes(fromaddr, toaddr-fromaddr)
                do_mem_map(mu, fromaddr, len(blk))
                mu.mem_write(fromaddr, blk)
            else: 
                blk = IDAAPI_GetManyBytes(toaddr, fromaddr+0x1000-toaddr) #if the end address is behind the star address, we map from end -> start+0x1000
                do_mem_map(mu, toaddr, len(blk))
                mu.mem_write(toaddr, blk)

    ################################################################################################
    
    def getPrintableCronobuf(self, session):
        printablecronobuf = dict()
        printablecronobuf["fullraw"] = str()
        printablecronobuf["areas"] = dict()
        #first, group all the written values by position
        for kv in session.cronomemwritten:
            curprintable = Utils.PrintableChars(kv[1])
            printablecronobuf["fullraw"] += curprintable
            for i in range(0, len(curprintable)):
                if kv[0]+i in printablecronobuf["areas"]: printablecronobuf["areas"][kv[0]+i].append(curprintable[i])
                else: printablecronobuf["areas"][kv[0]+i] = [curprintable[i]]
        sortedareas = dict()
        cursortedarea = -1
        prevaddr = -1
        #now, group written addresses in consecutive areas
        for e in sorted(printablecronobuf["areas"].keys()):
            print("prev", prevaddr, e)
            if prevaddr == -1 or e != prevaddr + 1:
                cursortedarea += 1
                sortedareas[cursortedarea] = dict()
            prevaddr = e
            sortedareas[cursortedarea][e] = printablecronobuf["areas"][e]
        printablecronobuf["areas"] = sortedareas
        return printablecronobuf

    ################################################################################################
    
    def printPrintableCronobufAreas(self, printablecronobuf):
        for curarea in sorted(printablecronobuf["areas"].keys()):
            print("area", curarea, printablecronobuf["areas"][curarea].keys())
            curareabuf = ""
            curareaaddr = printablecronobuf["areas"][curarea].keys()[0]
            for pos in sorted(printablecronobuf["areas"][curarea].keys()):
                print(pos, printablecronobuf["areas"][curarea][pos])
                curareabuf += printablecronobuf["areas"][curarea][pos][0]
                if len(printablecronobuf["areas"][curarea][pos])>1:
                    curareabuf += "("
                    for nextprintable in printablecronobuf["areas"][curarea][pos][1:]: curareabuf += nextprintable 
                    curareabuf += ")"
            self.gPrinter.doPrint("%s:%s" % (hex(curareaaddr), curareabuf), "emulator")

    ################################################################################################

    #registers is a dict, whose key is the name of the register and value the value to set to that register
    #memorycontents is a dict, whose key is an address and value is the content to set to that address
    #outoutcontentfrom is a dict, whouse key is an address whose content should be returned after emulation by this function (value is the size to recover)
    def emulateFromToInternal(self, emulation_params):

        fromaddr=emulation_params["fromaddr"]
        toaddr=emulation_params["toaddr"]
        registers=emulation_params["registers"]
        memorycontents=emulation_params["memorycontents"]
        outputregistersfrom=emulation_params["outputregistersfrom"]
        outputcontentfrom=emulation_params["outputcontentfrom"]
        mapmemwheninvalid=emulation_params["mapmemwheninvalid"]
        mapfullcode=emulation_params["mapfullcode"]
        debug=emulation_params["debug"]
        instoskip=emulation_params["instoskip"]
        nmaxins=emulation_params["nmaxins"]
        verbose=emulation_params["verbose"]
        startaddr_previns=emulation_params["startaddr_previns"]
        results2comments=emulation_params["results2comments"]

        resultscomment = ""
        session = AnalyzerEmulatorHooksSession(self)

        mu = session.unicornmod.Uc(session.unicornmod.UC_ARCH_X86, session.unicornmod.UC_MODE_32)

        for k, v in memorycontents.items():
            #print "memorycontents", k, v
            try: v = struct.pack("<L", v)
            except: pass
            do_mem_map(mu, k, len(v))
            mu.mem_write(k, v)

        for k, v in registers.items():
            exec("mu.reg_write(session.unicornctemod.UC_X86_REG_%s, %d)" % (k.upper(), v))

        if debug: session.debug = 1
        session.instoskip = instoskip
        session.maxcount = nmaxins

        if mapmemwheninvalid: mu.hook_add(session.unicornmod.UC_HOOK_MEM_READ_UNMAPPED | session.unicornmod.UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid, user_data=session)
        mu.hook_add(session.unicornmod.UC_HOOK_CODE, hook_code, user_data=session)
        mu.hook_add(session.unicornmod.UC_HOOK_MEM_WRITE, hook_mem_access, user_data=session)

        self.mapCodeDataFromIDA(mu, fromaddr, toaddr, mapfullcode)
        
        try: mu.emu_start(fromaddr, toaddr)
        except: pass

        outputmemorycontents={}
        outputregistercontents={}

        for k, v in outputcontentfrom.items():
            try: outputmemorycontents[k] = str(mu.mem_read(k, v))
            except: outputmemorycontents[k] = ""
        for k, v in outputregistersfrom.items():
            try: exec("outputregistercontents[k] = mu.reg_read(session.unicornctemod.UC_X86_REG_%s)" % k.upper())
            except: outputregistercontents[k] = 0

        if verbose:
            self.gPrinter.doPrint("Written memory:", "emulator")
            for k,v in session.memwritten.items():
                for vv in v:
                    self.gPrinter.doPrint(hex(k) + ":" + binascii.hexlify(vv) + "  ->  " + Utils.PrintableChars(vv), "emulator")
        
        if verbose:
            self.gPrinter.doPrint("Cronologic order written memory:", "emulator")
            for kv in session.cronomemwritten:
                curprintable = Utils.PrintableChars(kv[1])
                self.gPrinter.doPrint(hex(kv[0]) + ":" + binascii.hexlify(kv[1]) + "  ->  " + curprintable, "emulator")

        self.gPrinter.doPrint("Cronologic order written memory - cronobuf areas:", "emulator")
        printablecronobuf = self.getPrintableCronobuf(session)
        self.printPrintableCronobufAreas(printablecronobuf)
        
        if len(outputregistersfrom.items()):
            self.gPrinter.doPrint("Output registers configured by user:", "emulator")
            for k,v in outputregistersfrom.items():
                self.gPrinter.doPrint(k + ":" + hex(v), "emulator")
                resultscomment += (k + ":" + hex(v) + "\r\n")
                
        if len(outputmemorycontents.items()):
            self.gPrinter.doPrint("Output memory configured by user:", "emulator")
            for k,v in outputmemorycontents.items():
                self.gPrinter.doPrint(hex(k) + ":", "emulator")
                self.gPrinter.doPrint("    ->" + binascii.hexlify(v), "emulator")
                self.gPrinter.doPrint("    ->" + Utils.PrintableChars(v), "emulator")
                resultscomment += (hex(k) + ":\r\n")
                resultscomment += ("    ->" + binascii.hexlify(v) + "\r\n")
                resultscomment += ("    ->" + Utils.PrintableChars(v) + "\r\n")

        if results2comments:
            IDAAPI_MakeRptCmt(fromaddr, resultscomment)

    ################################################################################################

    def replaceWildcards(self, dct, wild, val):
        if val==None or wild==None or dct==None: return dct
        for k,v in dct.items():
            if type(v) is str and wild in v:
                dct[k] = val
        return dct

    ################################################################################################
    
    def expandFromaddrWildcard(self, wildcard, startaddr_previns):
        res = []
        lheaddis = Utils.GetIDAHeadsDisasm()
        for e in lheaddis:
            if wildcard in e[1]:
                addr = e[0]
                for i in range(0, startaddr_previns): addr = IDAAPI_PrevHead(addr)
                res.append(addr)
        return res

    ################################################################################################
    
    def emulateFromTo(self, emulation_params):
        
        #check enabled wildcards
        IDANAMESADDRESS1 = [None]
        IDANAMESADDRESS2 = [None]
        IDANAMESCONTENT1 = [None]
        IDANAMESCONTENT2 = [None]
        IMMOPERANDS1 = [None]
        IMMOPERANDS2 = [None]
        for k,v in emulation_params["registers"].items()+emulation_params["memorycontents"].items():
            if type(v) is str:
                if len(IDANAMESADDRESS1)==1 and IDANAMESADDRESS1[0]==None and "%IDANAMESADDRESS1%" in v:
                    IDANAMESADDRESS1 = Utils.GetIDANamesAddressesList(bNoCode=True)
                if len(IDANAMESADDRESS2)==1 and IDANAMESADDRESS2[0]==None and "%IDANAMESADDRESS2%" in v:
                    IDANAMESADDRESS2 = Utils.GetIDANamesAddressesList(bNoCode=True)
                if len(IDANAMESCONTENT1)==1 and IDANAMESCONTENT1[0]==None and "%IDANAMESCONTENT1%" in v:
                    sz = int(v.split("%IDANAMESCONTENT1%")[1].split("%")[0])
                    IDANAMESCONTENT1 = Utils.GetIDANamesContentsList(sz, bNoCode=True)
                if len(IDANAMESCONTENT2)==1 and IDANAMESCONTENT2[0]==None and "%IDANAMESCONTENT2%" in v:
                    sz = int(v.split("%IDANAMESCONTENT2%")[1].split("%")[0])
                    IDANAMESCONTENT2 = Utils.GetIDANamesContentsList(sz, bNoCode=True)
                if len(IMMOPERANDS1)==1 and IMMOPERANDS1[0]==None and "%IMMOPERANDS1%" in v:
                    IMMOPERANDS1 = Utils.GetInstructionsImmOperandsList()
                if len(IMMOPERANDS2)==1 and IMMOPERANDS2[0]==None and "%IMMOPERANDS2%" in v:
                    IMMOPERANDS2 = Utils.GetInstructionsImmOperandsList()
        #foreach enabled wildward, replace wildcard for value and emulate 
        for addr1 in IDANAMESADDRESS1:
            for addr2 in IDANAMESADDRESS2:
                for content1 in IDANAMESCONTENT1:
                    for content2 in IDANAMESCONTENT2:
                        for imm1 in IMMOPERANDS1:
                            for imm2 in IMMOPERANDS2:
                                if content1: content1 = content1["content"]
                                if content2: content2 = content2["content"]
                                replacedRegisters = emulation_params["registers"].copy()
                                replacedMemoryContents = emulation_params["memorycontents"].copy()
                                replacedRegisters = self.replaceWildcards(replacedRegisters, "%IDANAMESADDRESS1%", addr1)
                                replacedRegisters = self.replaceWildcards(replacedRegisters, "%IDANAMESADDRESS2%", addr2)
                                replacedRegisters = self.replaceWildcards(replacedRegisters, "%IDANAMESCONTENT1%", content1)
                                replacedRegisters = self.replaceWildcards(replacedRegisters, "%IDANAMESCONTENT2%", content2)
                                replacedRegisters = self.replaceWildcards(replacedRegisters, "%IMMOPERANDS1%", imm1)
                                replacedRegisters = self.replaceWildcards(replacedRegisters, "%IMMOPERANDS2%", imm2)
                                replacedMemoryContents = self.replaceWildcards(replacedMemoryContents, "%IDANAMESADDRESS1%", addr1)
                                replacedMemoryContents = self.replaceWildcards(replacedMemoryContents, "%IDANAMESADDRESS2%", addr2)
                                replacedMemoryContents = self.replaceWildcards(replacedMemoryContents, "%IDANAMESCONTENT1%", content1)
                                replacedMemoryContents = self.replaceWildcards(replacedMemoryContents, "%IDANAMESCONTENT2%", content2)
                                replacedMemoryContents = self.replaceWildcards(replacedMemoryContents, "%IMMOPERANDS1%", imm1)
                                replacedMemoryContents = self.replaceWildcards(replacedMemoryContents, "%IMMOPERANDS2%", imm2)
                                allfromaddr = []
                                if isinstance(emulation_params["fromaddr"], str): allfromaddr = self.expandFromaddrWildcard(emulation_params["fromaddr"], emulation_params["startaddr_previns"]) #emulate all the instructions whose disasm or comments contain the string in the variable fromaddr
                                else: allfromaddr = [emulation_params["fromaddr"]] #emulate target address
                                for curaddr in allfromaddr:
                                    self.gPrinter.doPrint("Starting emulation from %x to %x (nins %x)" % (curaddr, emulation_params["toaddr"], emulation_params["nmaxins"]), "emulator")
                                    self.gPrinter.doPrint("Registers:" + repr(replacedRegisters), "emulator")
                                    self.gPrinter.doPrint("MemoryContents:", "emulator")
                                    for k,v in replacedMemoryContents.items():
                                        try: v = binascii.hexlify(v)
                                        except: v = repr(v)
                                        if len(v)>20: v = v[0:20]
                                        self.gPrinter.doPrint(repr(k) + ":" + v, "emulator")
                                    emulation_internal_params = emulation_params.copy()
                                    emulation_internal_params["fromaddr"] = curaddr
                                    emulation_internal_params["registers"] = replacedRegisters
                                    emulation_internal_params["memorycontents"] = replacedMemoryContents
                                    #print "--------emulation_internal_params---------"
                                    #Utils.recursive_print(emulation_internal_params)
                                    self.emulateFromToInternal(emulation_internal_params)
