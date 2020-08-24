#
# idaDiscover plugin - by Javier Vicente Vallejo - @vallejocc
#

import struct

from menus import RegisterHotkeyAnalysisFull
from menus import RegisterHotkeySelectKey1
from menus import RegisterHotkeySelectContent1
from menus import RegisterHotkeyEmulateFromCurrentAddressWithDefaultCfg
from menus import RegisterHotkeySelectContent1FromAskString
from menus import RegisterHotkeySelectKey1FromAskString

import ConfigParser
import os
import sys
from printer import Printer
from installation import Installation
from utils import Utils
from ida_defines import *
import binascii
from analyzerstatistics import AnalyzerStatistic
#from analyzersignsrch import AnalyzerSignSrch
from analyzeryara import AnalyzerYara
from analyzerloops import AnalyzerLoops
from analyzercrypto import AnalyzerCrypto
from analyzeralgorithms import AnalyzerAlgorithms
from analyzerreferences import AnalyzerReferences
from menus import IDADiscoverConfigForm
from menus import RegisterMenus
from menus import RegisterHotkeys
from analyzeremulator import AnalyzerEmulator
from analyzerwindllcalls import AnalyzerWindllCalls

gPrinter = Printer()
gPrinter.Start()

####################################################################################################        

class IdaDiscover():
    
    ################################################################################################

    def __init__(self):
        global gPrinter
        self.emu_parameters_store = {}
        self.selectedKey1Range = (0, 0)
        self.selectedKey2Range = (0, 0)
        self.selectedContent1Range = (0, 0)
        self.selectedSearchBlockSize1 = 0
        self.selectedStringFromMenu = ""
        self.selectedKey1 = ""
        self.selectedKey2 = ""
        self.selectedContent1 = ""
        self.currentEa = 0
        self.currentEaEnd = 0
        self.config = ConfigParser.RawConfigParser()
        self.config.read(Utils.GetIniFilePath())
        self.yaraRulesPath = Utils.ReplaceAliasesAndPrepareString(self.config.get("run", "genconfig_yaraRulesPath"))        
        self.signSearchPath = Utils.ReplaceAliasesAndPrepareString(self.config.get("run", "genconfig_signSearchPath"))
        self.bColorizeLoops = True
        self.bAnalyzeLoops = True
        self.bAnalyzeHeuristicIdentificationAlgorithms = True
        self.bSearchEncryptedTexts = True
        self.bSearchMostUsedFunctions = True
        self.bSearchStackStrings = True
        self.bUpNameFunctions = True
        self.bApiCrc32UsageAnalysis = True
        self.ReloadConfig()
        self.Install()

    ################################################################################################
    
    def ReloadConfig(self):
        if self.config.get("run", "genconfig_bColorizeLoops")=="False": self.bColorizeLoops = False
        if self.config.get("run", "genconfig_bAnalyzeLoops")=="False": self.bAnalyzeLoops = False
        if self.config.get("run", "genconfig_bAnalyzeHeuristicIdentificationAlgorithms")=="False": self.bAnalyzeHeuristicIdentificationAlgorithms = False
        if self.config.get("run", "genconfig_bSearchEncryptedTxts")=="False": self.bSearchEncryptedTexts = False
        if self.config.get("run", "genconfig_bSearchMostUsedFunctions")=="False": self.bSearchMostUsedFunctions = False
        if self.config.get("run", "genconfig_bSearchStackStrings")=="False": self.bSearchStackStrings = False
        if self.config.get("run", "genconfig_bUpNameFunctions")=="False": self.bUpNameFunctions = False
        if self.config.get("run", "genconfig_bApiCrc32UsageAnalysis")=="False": self.bApiCrc32UsageAnalysis = False
        
    ################################################################################################

    def PrintEmuParametersStore(self):
        for k,v in self.emu_parameters_store.items():
            repr_v = repr(v)
            if len(repr_v)>40: repr_v = repr_v[0:40]
            print(repr(k), "->", repr_v)

    ################################################################################################

    def UpdateEmuParametersStore(self, l):
        for i in range(0, len(l)):
            if ":" in l[i][1]:
                paramkey = l[i][0]
                paramtype = l[i][1].split(":")[0]
                paramval = l[i][1][len(paramtype)+1:]
                if paramtype=='int': paramval = int(paramval, 16)
                if paramtype=='long': paramval = long(paramval, 16)
                self.emu_parameters_store[paramkey] = paramval

    ################################################################################################

    def EditEmuParametersStoreTransformValue(self, v):
        vtype = type(v).__name__
        if vtype=='int': return "int:%x" % v
        if vtype=='long': return "long:%x" % v
        if vtype=='str': return "str:%s" % v
        return "unkown:%s" % repr(v)

    ################################################################################################

    def EditEmuParametersStore(self):
        idaConfigForm = IDADiscoverConfigForm("Edit Emulation Config", [["Emulation Option", 20], ["Option Value", 20]], [[k, self.EditEmuParametersStoreTransformValue(v)] for k,v in self.emu_parameters_store.items()], self.UpdateEmuParametersStore)
        idaConfigForm.Show()

    ################################################################################################
    
    def ReloadModules(self):
        global gPrinter
        self.ReloadYaraRules()
        #self.signSrchAnalyzer = AnalyzerSignSrch(self.signSearchPath, gPrinter)
        self.loopsAnalyzer = AnalyzerLoops(gPrinter)
        self.cryptoAnalyzer = AnalyzerCrypto(gPrinter, self.GetApiNamesCrcs())
        self.algorithmsAnalyzer = AnalyzerAlgorithms(gPrinter)
        self.statisticAnalyzer = AnalyzerStatistic(gPrinter)
        self.referencesAnalyzer = AnalyzerReferences(gPrinter, self.GetCallTargetsToUpName())
        self.emulatorAnalyzer = AnalyzerEmulator(gPrinter)
        self.analyzerWindllCalls = AnalyzerWindllCalls(gPrinter)

    ################################################################################################
    
    def GetEncryptedTextsToSearch(self):
        enctxts = []
        for e in self.config.options("run"):
            if "encryptedtext" in e.lower():
                enctxt = self.config.get("run", e)
                enctxts.append(enctxt)
        return enctxts
    
    ################################################################################################
    
    def GetGenConfigs(self):
        genconfigs = []
        for e in self.config.options("run"):
            if "genconfig_" in e.lower():
                genconfig = self.config.get("run", e)
                genconfigs.append((e.replace("genconfig_", ""), genconfig))
        return genconfigs

    ################################################################################################
        
    def GetCallTargetsToUpName(self):
        calltargets = []
        for e in self.config.options("run"):
            if "calltarget" in e.lower():
                calltarget = self.config.get("run", e)
                calltargets.append(calltarget)
        return sorted(calltargets)
    
    ################################################################################################
    
    def GetApiNamesCrcs(self):
        apicrcs = []
        apinames = []
        for e in self.config.options("run"):
            if "apiname" in e.lower():
                apiname = self.config.get("run", e)
                apinames.append(apiname)
        for e in apinames: apicrcs.append((e, ("%08x" % (0xffffffff&binascii.crc32(e))).lower()))
        apicrcs = sorted(apicrcs, key=lambda apicrcs: apicrcs[1])
        return apicrcs
    
    ################################################################################################

    def GetApiNames(self):
        apinames = []
        for e in self.config.options("run"):
            if "apiname" in e.lower():
                apiname = self.config.get("run", e)
                apinames.append(apiname)
        return apinames
    
    ################################################################################################
    
    def UpdateGenConfigs(self, l):
        for e in self.config.options("run"):
            if "genconfig_" in e.lower():
                self.config.remove_option("run", e)
        for i in range(0, len(l)):
            self.config.set("run", "genconfig_%s" % l[i][0], l[i][1])
        f=Utils.OpenWriteIniFilePath()
        if not f:
            print("Unable to open config file")
        else: 
            self.config.write(f)
            f.close()
        self.ReloadConfig()
        
    ################################################################################################
    
    def UpdateCallTargets(self, l):
        for e in self.config.options("run"):
            if "calltarget" in e.lower():
                self.config.remove_option("run", e)
        for i in range(0, len(l)):
            self.config.set("run", "calltarget%d" % i, l[i][0])
        f=Utils.OpenWriteIniFilePath()
        if not f: 
            print("Unable to open config file")
        else: 
            self.config.write(f)
            f.close()
        self.ReloadConfig()

    ################################################################################################
    
    def UpdateApiNames(self, l):
        for e in self.config.options("run"):
            if "apiname" in e.lower():
                self.config.remove_option("run", e)
        for i in range(0, len(l)):
            self.config.set("run", "apiname%d" % i, l[i][0])
        f=Utils.OpenWriteIniFilePath()
        if not f: 
            print("Unable to open config file")
        else: 
            self.config.write(f)
            f.close()
        self.ReloadConfig()

    ################################################################################################
    
    def UpdateEncryptedTexts(self, l):
        for e in self.config.options("run"):
            if "encryptedtext" in e.lower():
                self.config.remove_option("run", e)
        for i in range(0, len(l)):
            self.config.set("run", "encryptedtext%d" % i, l[i][0])
        f=Utils.OpenWriteIniFilePath()
        if not f: 
            print("Unable to open config file")
        else: 
            self.config.write(f)
            f.close()
        self.ReloadConfig()

    ################################################################################################
    
    def FullAnalysis(self):
        global gPrinter
        gPrinter.Clear()
        if self.yaraRulesPath!="disabled": self.YaraAnalysis(clear=False)
        #if self.signSearchPath!="disabled": self.SignSrchAnalysis(clear=False)
        if self.bAnalyzeLoops: self.LoopsAnalysis(clear=False)
        if self.bAnalyzeHeuristicIdentificationAlgorithms: self.HeuristicIdentificationAlgorithmsAnalysis(clear=False)
        if self.bSearchEncryptedTexts: self.EncryptedTextAnalysis(clear=False)
        if self.bSearchMostUsedFunctions: self.MostUsedFunctionsAnalysis(clear=False)
        if self.bSearchStackStrings: idaDiscover.StackStringsAnalysis(clear=False)
        if self.bApiCrc32UsageAnalysis: idaDiscover.ApiCrc32UsageAnalysis(clear=False)
    
    ################################################################################################
    
    def YaraAnalysis(self, clear=True, binlineyara=False):
        global gPrinter
        if clear: gPrinter.Clear("yara")
        self.yaraAnalyzer.YaraMatchesToIdb(binlineyara=binlineyara)
    
    ################################################################################################
    
    #def SignSrchAnalysis(self, clear=True):
    #    global gPrinter
    #    if clear: gPrinter.Clear("signsrch")
    #    self.signSrchAnalyzer.SignSrchToIdb()
    
    ################################################################################################
    
    def LoopsAnalysis(self, clear=True):
        global gPrinter
        if clear: gPrinter.Clear("loops")
        self.loopsAnalyzer.AnalyzedLoopsToIdb(self.bColorizeLoops)

    ################################################################################################

    def EncryptedTextAnalysis(self, clear=True):
        global gPrinter
        if clear: gPrinter.Clear("crypto")
        self.cryptoAnalyzer.SearchEncryptedTextsToIdb(self.GetEncryptedTextsToSearch())

    ################################################################################################

    def HeuristicIdentificationAlgorithmsAnalysis(self, clear=True):
        global gPrinter
        if clear: gPrinter.Clear("algorithms")
        self.algorithmsAnalyzer.HeuristicIdentificationAlgorithms()
       
    ################################################################################################
    
    def MostUsedFunctionsAnalysis(self, clear=True):
        global gPrinter
        if clear: gPrinter.Clear("functions")
        self.statisticAnalyzer.SearchMostUsedFunctions(loopsAnalz=self.loopsAnalyzer)
    
    ################################################################################################
    
    def StackStringsAnalysisPermutedCode(self, clear=True):
        global gPrinter
        if clear: gPrinter.Clear("crypto")
        self.cryptoAnalyzer.SearchStackStringsToIdb(bPermutedCode = True)

    ################################################################################################
    
    def StackStringsAnalysis(self, clear=True):
        global gPrinter
        if clear: gPrinter.Clear("crypto")
        self.cryptoAnalyzer.SearchStackStringsToIdb(bPermutedCode = False)

    ################################################################################################

    def UpNameFunctionsAnalysis(self, clear=True):
        global gPrinter
        if clear: gPrinter.Clear("references")
        self.referencesAnalyzer.AnalyzeUpNames()

    ################################################################################################

    def UpNameFunctionsReset(self, clear=True):
        global gPrinter
        if clear: gPrinter.Clear("references")
        self.referencesAnalyzer.ResetUpNames()

    ################################################################################################
    
    def CreateFunctionsForUnreferencedCodeBlocks(self):
        global gPrinter
        self.referencesAnalyzer.CreateFunctionsForUnreferencedCodeBlocks()

    ################################################################################################
    
    def SetCandidateApiForDwords(self):
        self.analyzerWindllCalls.SetDwordsCandidateApi()

    ################################################################################################

    def Content1ToEmulatorMemoryAddress(self):
        addr = Utils.AskLongValue("\r\n\r\n- Emulator memory address - \r\n\r\n")
        self.emu_parameters_store["EMU_memcontent_%x" % addr] = self.selectedContent1
        self.PrintEmuParametersStore()

    ################################################################################################

    def EnterValueToEmulatorRegister(self):
        reg = Utils.AskTextValue("\r\n\r\n- Emulator register name - \r\n\r\n"+
                                 "Accepted values:\r\n\r\n"+ 
                                 "eax\r\n\r\n"+
                                 "ecx\r\n\r\n"+
                                 "edx\r\n\r\n"+
                                 "ebx\r\n\r\n"+
                                 "esp\r\n\r\n"+
                                 "ebp\r\n\r\n"+
                                 "esi\r\n\r\n"+
                                 "edi\r\n\r\n")
        v = Utils.AskLongValue("\r\n\r\n- Emulator register value - \r\n\r\n")
        self.emu_parameters_store["EMU_regvalue_%s" % reg] = v
        self.PrintEmuParametersStore()

    ################################################################################################

    def EnterValueToEmulatorMemoryAddress(self):
        addr = Utils.AskLongValue("\r\n\r\n- Emulator memory address - \r\n\r\n")
        v = Utils.AskLongValue("\r\n\r\n- Emulator memory address value - \r\n\r\n")
        self.emu_parameters_store["EMU_memcontent_%x" % addr] = struct.pack("<L", v)
        self.PrintEmuParametersStore()

    ################################################################################################

    def WildcardToEmulatorMemoryAddress(self):
        addr = Utils.AskLongValue("Emulator memory address")
        wild = Utils.AskTextValue("\r\n\r\n- Wildcard - \r\n\r\n"+
                                  "If you insert wildcards, the emulation will be launched N times.\r\n\r\n"+
                                  "For each emulation, the target emulator address will be filled with IDA addresses, data\r\n"+
                                  "or imm values, depending on the inserted wildcard.\r\n\r\n"+
                                  "CAREFUL: setting multiple wildcards could cause the emulation to take loooong time.\r\n\r\n\r\n"+
                                  "Accepted values\r\n\r\n"+
                                  "%IDANAMESADDRESS1% (addreses of the names of the IDA disassembly)\r\n\r\n"+
                                  "%IDANAMESADDRESS2% (identical like %IDANAMESADDRESS1%)\r\n\r\n"+
                                  "%IDANAMESCONTENT1%size% (the content at names of the IDA disassemble, size indicates the amount of bytes to be copied)\r\n\r\n"+
                                  "%IDANAMESCONTENT2%size% (identical like %IDANAMESCONTENT1%size%)\r\n\r\n"+
                                  "%IDANAMESCONTENT1%-1% (identical to %IDANAMESCONTENT1%size%, but the size is automatically set to the size of the block)\r\n\r\n"+
                                  "%IDANAMESCONTENT1%-2% (identical to %IDANAMESCONTENT1%-1%, but trailing zeroes are removed from the read data)\r\n\r\n"+
                                  "%IMMOPERANDS1% (imm operands among all the instructions of the IDA disassembly)\r\n\r\n"+
                                  "%IMMOPERANDS2% (identical like %IMMOPERANDS1%)\r\n\r\n")
        self.emu_parameters_store["EMU_memcontent_%x" % addr] = wild
        self.PrintEmuParametersStore()

    ################################################################################################

    def WildcardToEmulatorRegister(self):
        reg = Utils.AskTextValue("\r\n\r\n- Emulator register name - \r\n\r\n"+
                                 "Accepted values:\r\n\r\n"+ 
                                 "eax\r\n\r\n"+
                                 "ecx\r\n\r\n"+
                                 "edx\r\n\r\n"+
                                 "ebx\r\n\r\n"+
                                 "esp\r\n\r\n"+
                                 "ebp\r\n\r\n"+
                                 "esi\r\n\r\n"+
                                 "edi\r\n\r\n")
        wild = Utils.AskTextValue("\r\n\r\n- Wildcard - \r\n\r\n"+
                                  "If you insert wildcards, the emulation will be launched N times.\r\n\r\n"+
                                  "For each emulation, the target register will be filled with IDA addresses\r\n"+
                                  "or imm values, depending on the inserted wildcard.\r\n\r\n"+
                                  "CAREFUL: setting multiple wildcards could cause the emulation to take loooong time.\r\n\r\n\r\n"+
                                  "Accepted values\r\n\r\n"+
                                  "%IDANAMESADDRESS1% (addreses of the names of the IDA disassembly)\r\n\r\n"+
                                  "%IDANAMESADDRESS2% (identical like %IDANAMESADDRESS1%)\r\n\r\n"+
                                  "%IMMOPERANDS1% (imm operands among all the instructions of the IDA disassembly)\r\n\r\n"+
                                  "%IMMOPERANDS2% (identical like %IMMOPERANDS1%)\r\n\r\n")
        self.emu_parameters_store["EMU_regvalue_%s" % reg] = wild
        self.PrintEmuParametersStore()

    ################################################################################################

    def AskEmuVerboseOutput(self):
        verbose = Utils.AskYN("\r\n\r\n- Emulator - Enable verbose output? - \r\n\r\n")
        if verbose=="yes": self.emu_parameters_store["EMU_verbose"] = True
        if verbose=="no": self.emu_parameters_store["EMU_verbose"] = False
        self.PrintEmuParametersStore()

    ################################################################################################

    def SetStartAddressToEmulate(self):
        addr = Utils.AskLongValue("\r\n\r\n- Emulator - Configure emulation start address - \r\n\r\n")
        self.emu_parameters_store["EMU_startaddr"] = addr
        self.PrintEmuParametersStore()

    ################################################################################################

    def SetEndAddressToEmulate(self):
        addr = Utils.AskLongValue("\r\n\r\n- Emulator - Configure emulation end address - \r\n\r\n")
        self.emu_parameters_store["EMU_endaddr"] = addr
        self.PrintEmuParametersStore()

    ################################################################################################

    def SetRegisterToRecoverAfterEmulation(self):
        reg = Utils.AskTextValue("\r\n\r\n- Emulator - Configure register to recover once the emulation has finished  - \r\n\r\n")
        self.emu_parameters_store["EMU_outputregvalue_%s" % reg] = True
        self.PrintEmuParametersStore()

    ################################################################################################

    def SetMemoryAddressToRecoverAfterEmulation(self):
        addr = Utils.AskLongValue("\r\n\r\n- Emulator - Configure memory address to recover once the emulation has finished - \r\n\r\n")
        size = Utils.AskLongValue("\r\n\r\n- Emulator - Configure size of the memory address to recover once the emulation has finished - \r\n\r\n")
        self.emu_parameters_store["EMU_outputmemcontent_%x" % addr] = size
        self.PrintEmuParametersStore()

    ################################################################################################

    def SetFlagMapInvalidAddressWhileEmulation(self):
        if "yes"==Utils.AskYN("\r\n\r\n- Emulator - Map invalid address when they are accessed while emulation? - \r\n\r\n"):
            self.emu_parameters_store["EMU_mapinvalidaddresses"] = True
        else:
            self.emu_parameters_store["EMU_mapinvalidaddresses"] = False
        self.PrintEmuParametersStore()

    ################################################################################################

    def SetFlagMapFullCodeFromIdaSegments(self):
        if "yes"==Utils.AskYN("\r\n\r\n- Emulator - Map full code from IDA segments to emulator address space? - \r\n\r\n"):
            self.emu_parameters_store["EMU_mapfullcode"] = True
        else:
            self.emu_parameters_store["EMU_mapfullcode"] = False
        self.PrintEmuParametersStore()

    ################################################################################################

    def SetEmulatorDebugMode(self):
        if "yes"==Utils.AskYN("\r\n\r\n- Emulator - Enable emulator debug mode? - \r\n\r\n"):
            self.emu_parameters_store["EMU_debugmode"] = True
        else:
            self.emu_parameters_store["EMU_debugmode"] = False
        self.PrintEmuParametersStore()

    ################################################################################################

    def SetEmulatorResults2Comments(self):
        if "yes"==Utils.AskYN("\r\n\r\n- Emulator - Create IDA comments with emulation results? - \r\n\r\n"):
            self.emu_parameters_store["EMU_results2comments"] = True
        else:
            self.emu_parameters_store["EMU_results2comments"] = False
        self.PrintEmuParametersStore()

    ################################################################################################

    def SetMaxInsToEmulate(self):
        nins = Utils.AskLongValue("\r\n\r\n- Emulator - Set max number of ins to emulate - \r\n\r\n")
        self.emu_parameters_store["EMU_setmaxins"] = nins
        self.PrintEmuParametersStore()

    ################################################################################################

    def AddInstructionTypeToSkip(self):
        ins = Utils.AskTextValue("\r\n\r\n- Emulator - Instruction type to skip (for example, call, xor, etc...) - \r\n\r\n")
        self.emu_parameters_store["EMU_instoskip_%s" % ins] = True
        self.PrintEmuParametersStore()

    ################################################################################################
    
    def AddRecommendedInstructionsTypesToSkip(self):
        self.emu_parameters_store["EMU_instoskip_call dword ptr ["] = True
        self.PrintEmuParametersStore()
        print("Added instruction to skip: EMU_instoskip_call dword ptr [")

    ################################################################################################

    def InitEmulatorStack(self):
        self.emu_parameters_store["EMU_memcontent_0"] = 0x200000*"\x00"
        self.emu_parameters_store["EMU_regvalue_esp"] = 0x100000
        self.emu_parameters_store["EMU_regvalue_ebp"] = 0x100000
        self.PrintEmuParametersStore()

    ################################################################################################

    def ResetEmulationConfig(self):
        delit=[]
        for k,v in self.emu_parameters_store.items():
            if "EMU_" in k:
                delit.append(k)
        for k in delit:
            self.emu_parameters_store.pop(k)
        self.PrintEmuParametersStore()

    ################################################################################################

    def ShowCurrentEmulationConfig(self):
        self.PrintEmuParametersStore()
        print("Remember, if you emulate from current address with default config, the following config will be applied:")
        print("EMU_memcontent_0 = 0x200000*\"\\x00\"")
        print("EMU_regvalue_esp = 0x100000")
        print("EMU_regvalue_ebp = 0x100000")
        print("EMU_startaddr = 0x100000")
        print("EMU_endaddr = 0x99999999")
        print("EMU_mapfullcode = True")

    ################################################################################################

    def EmulateCurAddrDefaultCfg(self):
        self.InitEmulatorStack()
        self.emu_parameters_store["EMU_startaddr"] = IDAAPI_ScreenEA()
        self.emu_parameters_store["EMU_endaddr"] = 0x99999999
        self.emu_parameters_store["EMU_mapfullcode"] = True
        self.PrintEmuParametersStore()
        self.StartEmulation()

    ################################################################################################

    def EmulateCurAddrDefaultCfgAndWildcard(self):
        self.InitEmulatorStack()
        self.emu_parameters_store["EMU_startaddr"] = Utils.AskTextValue("\r\n\r\n- Emulator - Introduce an string that should be contained by the\r\ndisasm or comments of the instructions where emulation should start from.")
        self.emu_parameters_store["EMU_startaddr_previns"] = Utils.AskLongValue("\r\n\r\n- Emulator - Foreach match where the emulation shoult start,\r\nthe emulation will start a number of instructions previous to the match\r\n(this number of instructions is configured here).")
        self.emu_parameters_store["EMU_endaddr"] = 0x99999999
        self.emu_parameters_store["EMU_mapfullcode"] = True
        self.PrintEmuParametersStore()
        self.StartEmulation()

    ################################################################################################

    def StartEmulation(self):
        global gPrinter
        gPrinter.Clear("emulator")
        registers={}
        memorycontents={}
        outputregistersfrom={}
        outputcontentfrom={}
        instoskip={}
        mapmemwheninvalid=True
        mapfullcode=False
        debug=False
        fromaddr=0
        toaddr=0
        nmaxins=1000
        startaddr_previns = 0
        verbose=False
        results2comments=False
        for k,v in self.emu_parameters_store.items():
            if "EMU_regvalue_" in k: registers[k.replace("EMU_regvalue_", "")] = v
            if "EMU_memcontent_" in k: memorycontents[int(k.replace("EMU_memcontent_", ""), 16)] = v
            if "EMU_startaddr" in k: fromaddr = v
            if "EMU_endaddr" in k: toaddr = v
            if "EMU_outputregvalue_" in k: outputregistersfrom[k.replace("EMU_outputregvalue_", "")] = True
            if "EMU_outputmemcontent_" in k: outputcontentfrom[int(k.replace("EMU_outputmemcontent_", ""), 16)] = v
            if "EMU_mapinvalidaddresses" in k: mapmemwheninvalid = v
            if "EMU_mapfullcode" in k: mapfullcode = v
            if "EMU_debugmode" in k: debug = v
            if "EMU_instoskip_" in k: instoskip[k.replace("EMU_instoskip_", "")] = True
            if "EMU_setmaxins" in k: nmaxins = v
            if "EMU_verbose" in k: verbose = v
            if "EMU_startaddr_previns" in k: startaddr_previns = v
            if "EMU_results2comments" in k: results2comments = v
        emulation_params = {
            "fromaddr" : fromaddr,
            "toaddr" : toaddr,
            "registers" : registers,
            "memorycontents" : memorycontents,
            "outputregistersfrom" : outputregistersfrom,
            "outputcontentfrom" : outputcontentfrom,
            "mapmemwheninvalid" : mapmemwheninvalid,
            "mapfullcode" : mapfullcode,
            "debug" : debug,
            "instoskip" : instoskip,
            "nmaxins" : nmaxins,
            "verbose" : verbose, 
            "startaddr_previns" : startaddr_previns,
            "results2comments" : results2comments
        }
        self.emulatorAnalyzer.emulateFromTo(emulation_params)

    ################################################################################################

    def ApiCrc32UsageAnalysis(self, clear=True):
        global gPrinter
        if clear: gPrinter.Clear("crypto")
        self.cryptoAnalyzer.SearchApiCrc32UsageToIdb()

    ################################################################################################

    def Config(self):
        idaConfigForm = IDADiscoverConfigForm("Configuration", [["ConfigName", 20], ["Value", 20]], [[x[0], x[1]] for x in self.GetGenConfigs()], self.UpdateGenConfigs, disableDelete=True, disableInsert=True)
        idaConfigForm.Show()

    ################################################################################################
        
    def ConfigCallTargets(self):
        idaConfigForm = IDADiscoverConfigForm("Configure Call Targets", [["CallTargets", 20]], [[x] for x in self.GetCallTargetsToUpName()], self.UpdateCallTargets)
        idaConfigForm.Show()

    ################################################################################################
        
    def ConfigApiNames(self):
        idaConfigForm = IDADiscoverConfigForm("Configure Api Names", [["ApiNames", 20]], [[x] for x in self.GetApiNames()], self.UpdateApiNames)
        idaConfigForm.Show()
        
    ################################################################################################

    def ConfigEncryptedTexts(self):
        idaConfigForm = IDADiscoverConfigForm("Configure Encrypted Texts", [["EncryptedTexts", 20]], [[x] for x in self.GetEncryptedTextsToSearch()], self.UpdateEncryptedTexts)
        idaConfigForm.Show()

    ################################################################################################

    def Install(self):
        global gPrinter
        Installation.doInstall()
        self.ReloadModules()

    ################################################################################################

    def RemoveYaraRulesConflict(self):
        Installation.remove_yara_rules_conflict()
        self.ReloadYaraRules()

    ################################################################################################

    def ReloadYaraRules(self):
        global gPrinter
        self.yaraAnalyzer = AnalyzerYara(self.yaraRulesPath, gPrinter)
        
    ################################################################################################

    def SelectKey1(self):
        selected = IDAAPI_read_selection()
        self.selectedKey1  = IDAAPI_GetManyBytes(selected[1], selected[2]-selected[1])
        self.selectedKey1Range = (selected[1], selected[2])
        print("[+] select key 1: %x - %x, len: %x" % (selected[1],selected[2], selected[2]-selected[1]))

    ################################################################################################

    def SelectKey2(self):
        selected = IDAAPI_read_selection()
        self.selectedKey2 = IDAAPI_GetManyBytes(selected[1], selected[2]-selected[1])
        self.selectedKey2Range = (selected[1], selected[2])
        print("[+] select key 2: %x - %x, len: %x" % (selected[1],selected[2], selected[2]-selected[1]))

    ################################################################################################

    def SelectContent1(self):
        selected = IDAAPI_read_selection()
        self.selectedContent1 = IDAAPI_GetManyBytes(selected[1], selected[2]-selected[1])
        self.selectedContent1Range = (selected[1], selected[2])
        print("[+] select content 1: %x - %x, len: %x" % (selected[1],selected[2], selected[2]-selected[1]))

    ################################################################################################

    def WildcardToKey1(self):
        wild = Utils.AskTextValue("\r\n\r\n- Wildcard - \r\n\r\n"+
                                  "If you insert wildcards, some operations (for example crypto options) will be launched N times.\r\n\r\n"+
                                  "For each time, key1 will be filled with IDA data at different addresses (where IDA names were set)\r\n"+
                                  "or imm values, depending on the inserted wildcard.\r\n\r\n"+
                                  "CAREFUL: setting multiple wildcards could cause the operation to take loooong time.\r\n\r\n\r\n"+
                                  "Accepted values\r\n\r\n"+
                                  "%IDANAMESCONTENT1%size% (the content at names of the IDA disassemble, size indicates the amount of bytes to be copied)\r\n\r\n"+
                                  "%IDANAMESCONTENT2%size% (identical like %IDANAMESCONTENT1%size%)\r\n\r\n"+
                                  "%IDANAMESCONTENT1%-1% (identical to %IDANAMESCONTENT1%size%, but the size is automatically set to the size of the block)\r\n\r\n"+
                                  "%IDANAMESCONTENT1%-2% (identical to %IDANAMESCONTENT1%-1%, but trailing zeroes are removed from the read data)\r\n\r\n"+
                                  "%IMMOPERANDS1% (imm operands among all the instructions of the IDA disassembly)\r\n\r\n"+
                                  "%IMMOPERANDS2% (identical like %IMMOPERANDS1%)\r\n\r\n")
        self.selectedKey1  = wild
        self.selectedKey1Range = (0, 0)
        print("[+] wildcard - key 1: %s" % self.selectedKey1)

    ################################################################################################

    def WildcardToKey2(self):
        wild = Utils.AskTextValue("\r\n\r\n- Wildcard - \r\n\r\n"+
                                  "If you insert wildcards, some operations (for example crypto options) will be launched N times.\r\n\r\n"+
                                  "For each time, key2 will be filled with IDA data at different addresses (where IDA names were set)\r\n"+
                                  "or imm values, depending on the inserted wildcard.\r\n\r\n"+
                                  "CAREFUL: setting multiple wildcards could cause the operation to take loooong time.\r\n\r\n\r\n"+
                                  "Accepted values\r\n\r\n"+
                                  "%IDANAMESCONTENT1%size% (the content at names of the IDA disassemble, size indicates the amount of bytes to be copied)\r\n\r\n"+
                                  "%IDANAMESCONTENT2%size% (identical like %IDANAMESCONTENT1%size%)\r\n\r\n"+
                                  "%IDANAMESCONTENT1%-1% (identical to %IDANAMESCONTENT1%size%, but the size is automatically set to the size of the block)\r\n\r\n"+
                                  "%IDANAMESCONTENT1%-2% (identical to %IDANAMESCONTENT1%-1%, but trailing zeroes are removed from the read data)\r\n\r\n"+
                                  "%IMMOPERANDS1% (imm operands among all the instructions of the IDA disassembly)\r\n\r\n"+
                                  "%IMMOPERANDS2% (identical like %IMMOPERANDS1%)\r\n\r\n")
        self.selectedKey2  = wild
        self.selectedKey2Range = (0, 0)
        print("[+] wildcard - key 2: %s" % self.selectedKey2)

    ################################################################################################

    def WildcardToContent1(self):
        wild = Utils.AskTextValue("\r\n\r\n- Wildcard - \r\n\r\n"+
                                  "If you insert wildcards, some operations (for example crypto options) will be launched N times.\r\n\r\n"+
                                  "For each time, content1 will be filled with IDA data at different addresses (where IDA names were set)\r\n"+
                                  "or imm values, depending on the inserted wildcard.\r\n\r\n"+
                                  "CAREFUL: setting multiple wildcards could cause the operation to take loooong time.\r\n\r\n\r\n"+
                                  "Accepted values\r\n\r\n"+
                                  "%IDANAMESCONTENT1%size% (the content at names of the IDA disassemble, size indicates the amount of bytes to be copied)\r\n\r\n"+
                                  "%IDANAMESCONTENT2%size% (identical like %IDANAMESCONTENT1%size%)\r\n\r\n"+
                                  "%IDANAMESCONTENT1%-1% (identical to %IDANAMESCONTENT1%size%, but the size is automatically set to the size of the block)\r\n\r\n"+
                                  "%IDANAMESCONTENT1%-2% (identical to %IDANAMESCONTENT1%-1%, but trailing zeroes are removed from the read data)\r\n\r\n"+
                                  "%IMMOPERANDS1% (imm operands among all the instructions of the IDA disassembly)\r\n\r\n"+
                                  "%IMMOPERANDS2% (identical like %IMMOPERANDS1%)\r\n\r\n")
        self.selectedContent1 = wild
        self.selectedContent1Range = (0, 0)
        print("[+] wildcard - content 1: %s" % self.selectedContent1)

    ################################################################################################
    
    def ReverseKey1(self):
        if self.selectedKey1:
            self.selectedKey1 = self.selectedKey1[::-1]
            print("[+] crypto - reversed key 1")
        else:
            print("[-] crypto - reversed key 1 is null")

    ################################################################################################

    def ReverseKey2(self):
        if self.selectedKey2:
            self.selectedKey2 = self.selectedKey2[::-1]
            print("[+] crypto - reversed key 2")
        else:
            print("[-] crypto - reversed key 2 is null")

    ################################################################################################

    def ReverseContent1(self):
        if self.selectedContent1:
            self.selectedContent1 = self.selectedContent1[::-1]
            print("[+] crypto - reversed content 1")
        else:
            print("[-] crypto - reversed content 1 is null")

    ################################################################################################

    def SelectKey1FromFile(self):
        self.selectedKey1 = Utils.AskFileAndRead()
        if not self.selectedKey1: self.selectedKey1 = ""
        self.selectedKey1Range = (0, len(self.selectedKey1))
        print("[+] select key 1 len: %x" % len(self.selectedKey1))

    ################################################################################################

    def SelectKey2FromFile(self):
        self.selectedKey2 = Utils.AskFileAndRead()
        if not self.selectedKey2: self.selectedKey2 = ""
        self.selectedKey2Range = (0, len(self.selectedKey2))
        print("[+] select key 2 len: %x" % len(self.selectedKey2))

    ################################################################################################

    def SelectContent1FromFile(self):
        self.selectedContent1 = Utils.AskFileAndRead()
        if not self.selectedContent1: self.selectedContent1 = ""
        self.selectedContent1Range = (0, len(self.selectedContent1))
        print("[+] content 1 len: %x" % len(self.selectedContent1))

    ################################################################################################

    def SelectKey1FromAskRange(self):
        selected = Utils.AskAddressRange()
        self.selectedKey1 = IDAAPI_GetManyBytes(selected[0], selected[1]-selected[0])
        self.selectedKey1Range = selected
        print("[+] select key 1: %x - %x, len: %x, manybytes len: %x" % (selected[0],selected[1], selected[1]-selected[0], len(self.selectedKey1)))

    ################################################################################################

    def SelectKey2FromAskRange(self):
        selected = Utils.AskAddressRange()
        self.selectedKey2 = IDAAPI_GetManyBytes(selected[0], selected[1]-selected[0])
        self.selectedKey2Range = selected
        print("[+] select key 2: %x - %x, len: %x, manybytes len: %x" % (selected[0],selected[1], selected[1]-selected[0], len(self.selectedKey2)))

    ################################################################################################

    def SelectContent1FromAskRange(self):
        selected = Utils.AskAddressRange()
        self.selectedContent1 = IDAAPI_GetManyBytes(selected[0], selected[1]-selected[0])
        self.selectedContent1Range = selected
        print("[+] select content 1: %x - %x, len: %x, manybytes len: %x" % (selected[0],selected[1], selected[1]-selected[0], len(self.selectedContent1)))

    ################################################################################################

    def SetZeroesToContent1(self):
        sz = Utils.AskLongValue("\r\n\r\n- Select - Introduce size of buffer (filled with zeroes) to initialize content 1 - \r\n\r\n")
        self.selectedContent1 = "\x00" * sz

    ################################################################################################

    def SelectKey1FromAskString(self):
        self.selectedKey1 = Utils.AskStringUnescapeSeqHexa()
        selected = (0, len(self.selectedKey1))
        self.selectedKey1Range = selected
        print("[+] select key 1: %x - %x, len: %x, manybytes len: %x" % (selected[0],selected[1], selected[1]-selected[0], len(self.selectedKey1)))

    ################################################################################################

    def SelectKey2FromAskString(self):
        self.selectedKey2 = Utils.AskStringUnescapeSeqHexa()
        selected = (0, len(self.selectedKey2))
        self.selectedKey2Range = selected
        print("[+] select key 2: %x - %x, len: %x, manybytes len: %x" % (selected[0],selected[1], selected[1]-selected[0], len(self.selectedKey2)))

    ################################################################################################

    def SelectContent1FromAskString(self):
        self.selectedContent1 = Utils.AskStringUnescapeSeqHexa()
        selected = (0, len(self.selectedContent1))
        self.selectedContent1Range = selected
        print("[+] select content 1: %x - %x, len: %x, manybytes len: %x" % (selected[0],selected[1], selected[1]-selected[0], len(self.selectedContent1)))

    ################################################################################################
    
    def SelectSearchBlockSize1FromAskSize(self):
        self.selectedSearchBlockSize1 = Utils.AskSize()
        print("[+] select search block size: %x" % self.selectedSearchBlockSize1)

    ################################################################################################

    def SelectStringAcceptHexa1FromAskString(self):
        self.selectedStringFromMenu = Utils.AskStringUnescapeSeqHexa()
        print("[+] select string from menu 1: %s" % self.selectedStringFromMenu)

    ################################################################################################

    def ShowCurrentSelections(self):
        print("-------------------------------------------------------------------------------------")
        print("[+] Key 1:")
        print("Range: %x %x" % (self.selectedKey1Range[0], self.selectedKey1Range[1]))
        print(Utils.EscapeNonReadableCharacters(self.selectedKey1))
        print("[+] Key 2:")
        print("Range: %x %x" % (self.selectedKey2Range[0], self.selectedKey2Range[1]))
        print(Utils.EscapeNonReadableCharacters(self.selectedKey2))
        print("[+] Content 1:")
        print("Range: %x %x" % (self.selectedContent1Range[0], self.selectedContent1Range[1]))
        print(Utils.EscapeNonReadableCharacters(self.selectedContent1))
        print("[+] String from Menu:")
        print(Utils.EscapeNonReadableCharacters(self.selectedStringFromMenu))
        print("[+] Search Block Size1:")
        print(self.selectedSearchBlockSize1)
        print("-------------------------------------------------------------------------------------")

    ################################################################################################

    def UpdateSelections(self, l):
        for i in range(0, len(l)):
            if ":" in l[i][1]:
                paramkey = l[i][0]
                paramtype = l[i][1].split(":")[0]
                paramval = l[i][1][len(paramtype)+1:]
                if paramtype=='int': paramval = int(paramval, 16)
                if paramtype=='long': paramval = long(paramval, 16)
                if paramtype=='str': paramval = Utils.UnescapeSeqHexa(paramval)
                if paramkey == "selectedKey1RangeStart" : self.selectedKey1Range = (paramval, self.selectedKey1Range[1])
                if paramkey == "selectedKey1RangeEnd" : self.selectedKey1Range = (self.selectedKey1Range[0], paramval)
                if paramkey == "selectedKey1" : self.selectedKey1 = paramval
                if paramkey == "selectedKey2RangeStart" : self.selectedKey2Range = (paramval, self.selectedKey2Range[1])
                if paramkey == "selectedKey2RangeEnd" : self.selectedKey2Range = (self.selectedKey2Range[0], paramval)
                if paramkey == "selectedKey2" : self.selectedKey2 = paramval
                if paramkey == "selectedContent1RangeStart" : self.selectedContent1Range = (paramval, self.selectedContent1Range[1])
                if paramkey == "selectedContent1RangeEnd" : self.selectedContent1Range = (self.selectedContent1Range[0], paramval)
                if paramkey == "selectedContent1" : self.selectedContent1 = paramval
                if paramkey == "selectedStringFromMenu" : self.selectedStringFromMenu = paramval
                if paramkey == "selectedSearchBlockSize1" : self.selectedSearchBlockSize1 = paramval

    ################################################################################################

    def EditCurrentSelectionsTransformValue(self, v):
        vtype = type(v).__name__
        if vtype=='int': return "int:%x" % v
        if vtype=='long': return "long:%x" % v
        if vtype=='str': return "str:%s" % Utils.EscapeNonReadableCharacters(v)
        return "unkown:%s" % repr(v)

    ################################################################################################

    def EditCurrentSelections(self):
        selections = {
            "selectedKey1RangeStart" : self.selectedKey1Range[0],
            "selectedKey1RangeEnd" : self.selectedKey1Range[1],
            "selectedKey1" : self.selectedKey1,
            "selectedKey2RangeStart" : self.selectedKey2Range[0],
            "selectedKey2RangeEnd" : self.selectedKey2Range[1],
            "selectedKey2" : self.selectedKey2,
            "selectedContent1RangeStart" : self.selectedContent1Range[0],
            "selectedContent1RangeEnd" : self.selectedContent1Range[1],
            "selectedContent1" : self.selectedContent1,
            "selectedStringFromMenu" : self.selectedStringFromMenu,
            "selectedSearchBlockSize1" : self.selectedSearchBlockSize1 
        }
        idaConfigForm = IDADiscoverConfigForm("Edit Selections", [["Selection", 20], ["Option Value", 20]], [[k, self.EditCurrentSelectionsTransformValue(v)] for k,v in selections.items()], self.UpdateSelections)
        idaConfigForm.Show()

    ################################################################################################

    def CalculateRc4(self):
        self.cryptoAnalyzer.DoCrypto("RC4", self.selectedContent1, self.selectedKey1, self.selectedKey2)

    ################################################################################################

    def CalculateAesCbc(self):
        self.cryptoAnalyzer.DoCrypto("AES CBC", self.selectedContent1, self.selectedKey1, self.selectedKey2)

    ################################################################################################

    def CalculateAesEcb(self):
        self.cryptoAnalyzer.DoCrypto("AES ECB", self.selectedContent1, self.selectedKey1, self.selectedKey2)

    ################################################################################################

    def CalculateXor(self):
        self.cryptoAnalyzer.DoCrypto("XOR", self.selectedContent1, self.selectedKey1, self.selectedKey2)

    ################################################################################################

    def CalculateMd5(self):
        self.cryptoAnalyzer.DoCrypto("MD5", self.selectedContent1, self.selectedKey1, self.selectedKey2)

    ################################################################################################

    def CalculateSha256(self):
        self.cryptoAnalyzer.DoCrypto("SHA256", self.selectedContent1, self.selectedKey1, self.selectedKey2)

    ################################################################################################
    
    def SearchEncryptedRc4(self):
        print("Len selected content %x" % len(self.selectedContent1))
        print("Search block size %x" % self.selectedSearchBlockSize1)
        print("Encrypted string to search %s" % self.selectedStringFromMenu)
        l = self.cryptoAnalyzer.SearchEncryptedRc4(self.selectedContent1, self.selectedKey1, self.selectedSearchBlockSize1, self.selectedStringFromMenu)
        for i in l: print("Rc4 encrypted string found at address %x" % (self.selectedContent1Range[0]+i))
        if not len(l): print("Rc4 encrypted string not found")

    ################################################################################################

    def SearchEncryptedAesCbc(self):
        print("Len selected content %x" % len(self.selectedContent1))
        print("Search block size %x" % self.selectedSearchBlockSize1)
        print("Encrypted string to search %s" % self.selectedStringFromMenu)
        l = self.cryptoAnalyzer.SearchEncryptedAes(self.selectedContent1, self.selectedKey1, self.selectedKey2, self.selectedSearchBlockSize1, self.selectedStringFromMenu, 0)
        for i in l: print("Aes cbc encrypted string found at address %x" % (self.selectedContent1Range[0]+i))
        if not len(l): print("Aes cbc encrypted string not found")

    ################################################################################################

    def SearchEncryptedAesEcb(self):
        print("Len selected content %x" % len(self.selectedContent1))
        print("Search block size %x" % self.selectedSearchBlockSize1)
        print("Encrypted string to search %s" % self.selectedStringFromMenu)
        l = self.cryptoAnalyzer.SearchEncryptedAes(self.selectedContent1, self.selectedKey1, self.selectedKey2, self.selectedSearchBlockSize1, self.selectedStringFromMenu, 1)
        for i in l: print("Aes ecb encrypted string found at address %x" % (self.selectedContent1Range[0]+i))
        if not len(l): print("Aes ecb string not found")

    ################################################################################################

    def SearchEncryptedXor(self):
        print("Len selected content %x" % len(self.selectedContent1))
        print("Search block size %x" % self.selectedSearchBlockSize1)
        print("Encrypted string to search %s" % self.selectedStringFromMenu)
        l = self.cryptoAnalyzer.SearchEncryptedXor(self.selectedContent1, self.selectedKey1, self.selectedSearchBlockSize1, self.selectedStringFromMenu)
        for i in l: print("Xor encrypted string found at address %x" % (self.selectedContent1Range[0]+i))
        if not len(l): print("Xor encrypted string not found")

####################################################################################################

print(sys.version)
idaDiscover = IdaDiscover()
RegisterMenus(idaDiscover)
RegisterHotkeys(idaDiscover)

