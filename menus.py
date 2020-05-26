from utils import Utils
from ida_defines import *

class TestEmbeddedChooserClass(IDAAPI_Choose):
    """
    A simple chooser to be used as an embedded chooser
    """
    def __init__(self, title, nb = 5, flags=0):
        IDAAPI_Choose.__init__(self,
                         title,
                         [ ["Address", 10], ["Name", 30] ],
                         embedded=True, width=30, height=20, flags=flags)
        self.n = 0
        self.items = [ self.make_item() for x in xrange(0, nb+1) ]
        self.icon = 5
        self.selcount = 0

    def make_item(self):
        r = [str(self.n), "func_%04d" % self.n]
        self.n += 1
        return r

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        print("getsize -> %d" % n)
        return n

class IDADiscoverConfigForm2(Form):
    def __init__(self):
        self.invert = False
        self.EChooser = TestEmbeddedChooserClass("E1", flags=IDAAPI_Choose.CH_MULTI)
        IDAAPI_Form.__init__(self, r"""STARTITEM {id:rNormal}
                            BUTTON YES* Yeah
                            BUTTON NO Nope
                            BUTTON CANCEL Nevermind
                            Form Test
                            {FormChangeCb}
                            This is a string: +{cStr1}+
                            This is an address: +{cAddr1}+
                            Escape\{control}
                            This is a string: '{cStr2}'
                            This is a number: {cVal1}
                            <#Hint1#Enter name:{iStr1}>
                            <#Hint2#Select color:{iColor1}>
                            Browse test
                            <#Select a file to open#Browse to open:{iFileOpen}>
                            <#Select a file to save#Browse to save:{iFileSave}>
                            <#Select dir#Browse for dir:{iDir}>
                            Type
                            <#Select type#Write a type:{iType}>
                            Numbers
                            <##Enter a selector value:{iSegment}>
                            <##Enter a raw hex:{iRawHex}>
                            <##Enter a character:{iChar}>
                            <##Enter an address:{iAddr}>
                            Button test
                            <##Button1:{iButton1}> <##Button2:{iButton2}>
                            Check boxes:
                            <Error output:{rError}>
                            <Normal output:{rNormal}>
                            <Warnings:{rWarnings}>{cGroup1}>
                            Radio boxes:
                            <Green:{rGreen}>
                            <Red:{rRed}>
                            <Blue:{rBlue}>{cGroup2}>
                            <Embedded chooser:{cEChooser}>
                            The end!
                            """, {
                            'cStr1': IDAAPI_Form.StringLabel("Hello"),
                            'cStr2': IDAAPI_Form.StringLabel("StringTest"),
                            'cAddr1': IDAAPI_Form.NumericLabel(0x401000, IDAAPI_Form.FT_ADDR),
                            'cVal1' : IDAAPI_Form.NumericLabel(99, IDAAPI_Form.FT_HEX),
                            'iStr1': IDAAPI_Form.StringInput(),
                            'iColor1': IDAAPI_Form.ColorInput(),
                            'iFileOpen': IDAAPI_Form.FileInput(open=True),
                            'iFileSave': IDAAPI_Form.FileInput(save=True),
                            'iDir': IDAAPI_Form.DirInput(),
                            'iType': IDAAPI_Form.StringInput(tp=IDAAPI_Form.FT_TYPE),
                            'iSegment': IDAAPI_Form.NumericInput(tp=IDAAPI_Form.FT_SEG),
                            'iRawHex': IDAAPI_Form.NumericInput(tp=IDAAPI_Form.FT_RAWHEX),
                            'iAddr': IDAAPI_Form.NumericInput(tp=IDAAPI_Form.FT_ADDR),
                            'iChar': IDAAPI_Form.NumericInput(tp=IDAAPI_Form.FT_CHAR),
                            'iButton1': IDAAPI_Form.ButtonInput(self.OnButton1),
                            'iButton2': IDAAPI_Form.ButtonInput(self.OnButton2),
                            'cGroup1': IDAAPI_Form.ChkGroupControl(("rNormal", "rError", "rWarnings")),
                            'cGroup2': IDAAPI_Form.RadGroupControl(("rRed", "rGreen", "rBlue")),
                            'FormChangeCb': IDAAPI_Form.FormChangeCb(self.OnFormChange),
                            'cEChooser' : IDAAPI_Form.EmbeddedChooserControl(self.EChooser)
                        })

    def OnButton1(self, code=0):
        print("Button1 pressed")


    def OnButton2(self, code=0):
        print("Button2 pressed")


    def OnFormChange(self, fid):
        if fid == self.iButton1.id:
            print("Button1 fchg;inv=%s" % self.invert)
            self.SetFocusedField(self.rNormal)
            self.EnableField(self.rError, self.invert)
            self.invert = not self.invert
        elif fid == self.iButton2.id:
            g1 = self.GetControlValue(self.cGroup1)
            g2 = self.GetControlValue(self.cGroup2)
            d = self.GetControlValue(self.iDir)
            f = self.GetControlValue(self.iFileOpen)
            print("cGroup2:%x;Dir=%s;fopen=%s;cGroup1:%x" % (g1, d, f, g2))
        elif fid == self.cEChooser.id:
            l = self.GetControlValue(self.cEChooser)
            print("Chooser: %s" % l)
        else:
            print(">>fid:%d" % fid)
        return 1


####################################################################################################        
####################################################################################################        
####################################################################################################        

class IDADiscoverConfigForm(IDAAPI_Choose):
    
    #sample colums:   columns = [ ["Address", 10], ["Name", 30] ]
    #sample items:    items =   [[ aaaa, bbbb ],
    #                            [ cccc, dddd ],
    #                            ...]

    def __init__(self, title, columns, items, save_callback=None, nb = 5, flags=IDAAPI_Choose.CH_MULTI, width=None, height=None, embedded=False, modal=False, disableDelete=False, disableInsert=False):
        IDAAPI_Choose.__init__(
            self,
            title,
            columns,
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)
        self.ncolumns = len(columns)
        self.items = []
        self.items.append(["-------"]*self.ncolumns)
        self.items.extend(items)
        self.icon = 5
        self.modal = modal
        self.save_callback = save_callback
        self.disableDelete = disableDelete
        self.disableInsert = disableInsert

    def MyRefresh(self):
        self.Refresh()

    def OnClose(self):
        pass

    def OnEditLine(self, n):
        #print "OnEditLine", n 
        if not len(n): return True
        for nn in n:
            if nn != 0:
                for column in range(0, len(self.items[nn])):
                    s = IDAAPI_AskStr(Utils.UnQuote(repr(self.items[nn][column])), 'Enter text for column %d:'%column)
                    if s:
                        self.items[nn][column] = s
                        if self.save_callback:
                            self.save_callback(self.items[1:])
        self.MyRefresh()

    def OnInsertLine(self, n):
        #print "OnInsertLine", n       
        if not self.disableInsert:
            self.items.append([""]*self.ncolumns)
            self.MyRefresh()

    def OnSelectLine(self, n):
        #print "OnSelectLine", n
        return n
        
    def OnSelectionChange(self, n):
        #print  "OnSelectionChange", n
        return n

    def OnGetLine(self, n):
        #print "OnGetLine", n
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        #print "OnGetSize", n
        return n

    def OnDeleteLine(self, n):
        #print "OnDeleteLine", n
        if self.disableDelete: return True
        if not len(n): return True
        deletelist = n
        for n in deletelist:
            if n!=0:
                self.items[n]=None
        self.items = [x for x in self.items if x != None]
        self.MyRefresh()
        if self.save_callback:
            self.save_callback(self.items[1:])
        return True

    def OnRefresh(self, n):
        #print "OnRefresh", n
        return n

    def OnGetIcon(self, n):
        #print "OnGetIcon", n
        return self.icon

    def show(self):
        #print "show"
        return self.Show(self.modal) >= 0
        
    def OnGetLineAttr(self, n):
        #print "OnGetLineAttr", n
        return [0xFFFFFF, 0]

    def OnActivate(self):
        #print "OnActivate"
        pass

####################################################################################################        
####################################################################################################        
####################################################################################################        


class IDADiscoverMenu(IDAAPI_action_handler_t):
    
    def __init__(self, id, idaDiscover):
        self.curMenu=""
        self.idaDiscover=idaDiscover
        if id==1: self.curMenu="config"
        if id==2: self.curMenu="install"
        if id==3: self.curMenu="analysis_full"
        if id==4: self.curMenu="analysis_yara"
        #if id==5: self.curMenu="analysis_signsrch"
        if id==6: self.curMenu="analysis_loops"
        if id==7: self.curMenu="analysis_encrypted_text"
        if id==8: self.curMenu="analysis_heuristic_identification_algorithms"
        if id==9: self.curMenu="analysis_most_used_functions"
        if id==10: self.curMenu="analysis_stack_strings"
        if id==11: self.curMenu="analysis_stack_strings_permuted_code"
        if id==12: self.curMenu="analysis_upname_functions"
        if id==13: self.curMenu="analysis_apicrc32_usage"
        if id==14: self.curMenu="reset_upname_functions"
        if id==15: self.curMenu="select_key_1"
        if id==16: self.curMenu="select_key_2"
        if id==17: self.curMenu="select_content_1"
        if id==18: self.curMenu="calculate_rc4"
        if id==19: self.curMenu="calculate_aes_cbc"
        if id==20: self.curMenu="calculate_aes_ecb"
        if id==21: self.curMenu="calculate_xor"
        if id==22: self.curMenu="calculate_md5"
        if id==23: self.curMenu="calculate_sha256"
        if id==24: self.curMenu="select_key_1_from_file"
        if id==25: self.curMenu="select_key_2_from_file"
        if id==26: self.curMenu="select_content_1_from_file"
        if id==27: self.curMenu="remove_yara_rules_conflicts"
        if id==28: self.curMenu="reload_yara_rules"
        if id==29: self.curMenu="reload_modules"
        if id==30: self.curMenu="config_call_targets"
        if id==31: self.curMenu="config_api_names"
        if id==32: self.curMenu="config_encrypted_texts"
        if id==33: self.curMenu="select_key_1_from_ask_range"
        if id==34: self.curMenu="select_key_2_from_ask_range"
        if id==35: self.curMenu="select_content_1_from_ask_range"
        if id==36: self.curMenu="select_search_block_size_1_from_ask_size"
        if id==37: self.curMenu="select_string_accept_hexa_1_from_ask_string"
        if id==38: self.curMenu="search_string_encrypted_with_rc4"
        if id==39: self.curMenu="search_string_encrypted_with_aes_cbc"
        if id==40: self.curMenu="search_string_encrypted_with_aes_ecb"
        if id==41: self.curMenu="search_string_encrypted_with_xor"
        if id==42: self.curMenu="select_key_1_from_ask_string"
        if id==43: self.curMenu="select_key_2_from_ask_string"
        if id==44: self.curMenu="select_content_1_from_ask_string"
        if id==45: self.curMenu="create_functions_for_unreferenced_code_blocks"
        if id==46: self.curMenu="content1_to_emulator_memory_address"
        if id==47: self.curMenu="enter_value_to_emulator_register"
        if id==48: self.curMenu="set_start_address_to_emulate"
        if id==49: self.curMenu="set_end_address_to_emulate"
        if id==50: self.curMenu="set_register_to_recover_after_emulation"
        if id==51: self.curMenu="set_memory_address_to_recover_after_emulation"
        if id==52: self.curMenu="set_flag_to_map_or_not_invalid_addresses_while_emulation"
        if id==53: self.curMenu="set_flag_to_map_or_not_the_full_code_from_ida_segments"
        if id==54: self.curMenu="reset_emulation_config"
        if id==55: self.curMenu="start_emulation"
        if id==56: self.curMenu="set_emulator_debug_mode"
        if id==57: self.curMenu="set_zeros_to_content1"
        if id==58: self.curMenu="init_emulator_stack"
        if id==59: self.curMenu="add_instruction_type_to_skip"
        if id==60: self.curMenu="set_max_ins_to_emulate"
        if id==61: self.curMenu="emulate_curaddr_default_cfg"
        if id==62: self.curMenu="wildcard_to_emulator_memory_address"
        if id==63: self.curMenu="wildcard_to_emulator_register"
        if id==64: self.curMenu="emulation_verbose_output"
        if id==65: self.curMenu="add_recommended_instructions_types_to_skip"
        if id==66: self.curMenu="show_current_emulation_config"
        if id==67: self.curMenu="emulate_curaddr_default_cfg_and_wildcard"
        if id==68: self.curMenu="set_emulator_results2comments"
        if id==69: self.curMenu="set_candidate_api_for_dwords"
        if id==70: self.curMenu="enter_value_to_emulator_memory_address"
        if id==71: self.curMenu="introduce_wildcard_to_key1"
        if id==72: self.curMenu="introduce_wildcard_to_key2"
        if id==73: self.curMenu="introduce_wildcard_to_content1"
        if id==74: self.curMenu="edit_emu_parameters_store"
        if id==75: self.curMenu="show_current_selections"
        if id==76: self.curMenu="edit_current_selections"
        IDAAPI_action_handler_t.__init__(self)

    def activate(self, ctx):
        if self.curMenu=="config": self.idaDiscover.Config()
        if self.curMenu=="install": self.idaDiscover.Install()
        if self.curMenu=="analysis_full": self.idaDiscover.FullAnalysis()
        if self.curMenu=="analysis_yara": self.idaDiscover.YaraAnalysis()
        #if self.curMenu=="analysis_signsrch": self.idaDiscover.SignSrchAnalysis()
        if self.curMenu=="analysis_loops": self.idaDiscover.LoopsAnalysis()
        if self.curMenu=="analysis_encrypted_text": self.idaDiscover.EncryptedTextAnalysis()
        if self.curMenu=="analysis_heuristic_identification_algorithms": self.idaDiscover.HeuristicIdentificationAlgorithmsAnalysis()
        if self.curMenu=="analysis_most_used_functions": self.idaDiscover.MostUsedFunctionsAnalysis()
        if self.curMenu=="analysis_stack_strings": self.idaDiscover.StackStringsAnalysis()
        if self.curMenu=="analysis_stack_strings_permuted_code": self.idaDiscover.StackStringsAnalysisPermutedCode()
        if self.curMenu=="analysis_upname_functions": self.idaDiscover.UpNameFunctionsAnalysis()
        if self.curMenu=="analysis_apicrc32_usage": self.idaDiscover.ApiCrc32UsageAnalysis()
        if self.curMenu=="reset_upname_functions": self.idaDiscover.UpNameFunctionsReset()
        if self.curMenu=="select_key_1": self.idaDiscover.SelectKey1()
        if self.curMenu=="select_key_2": self.idaDiscover.SelectKey2()
        if self.curMenu=="select_content_1": self.idaDiscover.SelectContent1()
        if self.curMenu=="calculate_rc4": self.idaDiscover.CalculateRc4()
        if self.curMenu=="calculate_aes_cbc": self.idaDiscover.CalculateAesCbc()
        if self.curMenu=="calculate_aes_ecb": self.idaDiscover.CalculateAesEcb()
        if self.curMenu=="calculate_xor": self.idaDiscover.CalculateXor()
        if self.curMenu=="calculate_md5": self.idaDiscover.CalculateMd5()
        if self.curMenu=="calculate_sha256": self.idaDiscover.CalculateSha256()
        if self.curMenu=="select_key_1_from_file": self.idaDiscover.SelectKey1FromFile()
        if self.curMenu=="select_key_2_from_file": self.idaDiscover.SelectKey2FromFile()
        if self.curMenu=="select_content_1_from_file": self.idaDiscover.SelectContent1FromFile()
        if self.curMenu=="remove_yara_rules_conflicts": self.idaDiscover.RemoveYaraRulesConflict()
        if self.curMenu=="reload_yara_rules": self.idaDiscover.ReloadYaraRules()
        if self.curMenu=="reload_modules": self.idaDiscover.ReloadModules()
        if self.curMenu=="config_call_targets": self.idaDiscover.ConfigCallTargets()
        if self.curMenu=="config_api_names": self.idaDiscover.ConfigApiNames()
        if self.curMenu=="config_encrypted_texts": self.idaDiscover.ConfigEncryptedTexts()
        if self.curMenu=="select_key_1_from_ask_range": self.idaDiscover.SelectKey1FromAskRange()
        if self.curMenu=="select_key_2_from_ask_range": self.idaDiscover.SelectKey2FromAskRange()
        if self.curMenu=="select_content_1_from_ask_range": self.idaDiscover.SelectContent1FromAskRange()
        if self.curMenu=="select_search_block_size_1_from_ask_size": self.idaDiscover.SelectSearchBlockSize1FromAskSize()
        if self.curMenu=="select_string_accept_hexa_1_from_ask_string": self.idaDiscover.SelectStringAcceptHexa1FromAskString()
        if self.curMenu=="search_string_encrypted_with_rc4": self.idaDiscover.SearchEncryptedRc4()
        if self.curMenu=="search_string_encrypted_with_aes_cbc": self.idaDiscover.SearchEncryptedAesCbc()
        if self.curMenu=="search_string_encrypted_with_aes_ecb": self.idaDiscover.SearchEncryptedAesEcb()
        if self.curMenu=="search_string_encrypted_with_xor": self.idaDiscover.SearchEncryptedXor()
        if self.curMenu=="select_key_1_from_ask_string": self.idaDiscover.SelectKey1FromAskString()
        if self.curMenu=="select_key_2_from_ask_string": self.idaDiscover.SelectKey2FromAskString()
        if self.curMenu=="select_content_1_from_ask_string": self.idaDiscover.SelectContent1FromAskString()
        if self.curMenu=="create_functions_for_unreferenced_code_blocks": self.idaDiscover.CreateFunctionsForUnreferencedCodeBlocks()
        if self.curMenu=="content1_to_emulator_memory_address": self.idaDiscover.Content1ToEmulatorMemoryAddress()
        if self.curMenu=="enter_value_to_emulator_register": self.idaDiscover.EnterValueToEmulatorRegister()
        if self.curMenu=="set_start_address_to_emulate": self.idaDiscover.SetStartAddressToEmulate()
        if self.curMenu=="set_end_address_to_emulate": self.idaDiscover.SetEndAddressToEmulate()
        if self.curMenu=="set_register_to_recover_after_emulation": self.idaDiscover.SetRegisterToRecoverAfterEmulation()
        if self.curMenu=="set_memory_address_to_recover_after_emulation": self.idaDiscover.SetMemoryAddressToRecoverAfterEmulation()
        if self.curMenu=="set_flag_to_map_or_not_invalid_addresses_while_emulation": self.idaDiscover.SetFlagMapInvalidAddressWhileEmulation()
        if self.curMenu=="set_flag_to_map_or_not_the_full_code_from_ida_segments": self.idaDiscover.SetFlagMapFullCodeFromIdaSegments()
        if self.curMenu=="reset_emulation_config": self.idaDiscover.ResetEmulationConfig()
        if self.curMenu=="start_emulation": self.idaDiscover.StartEmulation()
        if self.curMenu=="set_emulator_debug_mode": self.idaDiscover.SetEmulatorDebugMode()
        if self.curMenu=="set_zeros_to_content1": self.idaDiscover.SetZeroesToContent1()
        if self.curMenu=="init_emulator_stack": self.idaDiscover.InitEmulatorStack()
        if self.curMenu=="add_instruction_type_to_skip": self.idaDiscover.AddInstructionTypeToSkip()
        if self.curMenu=="add_recommended_instructions_types_to_skip": self.idaDiscover.AddRecommendedInstructionsTypesToSkip()
        if self.curMenu=="set_max_ins_to_emulate": self.idaDiscover.SetMaxInsToEmulate()
        if self.curMenu=="emulate_curaddr_default_cfg": self.idaDiscover.EmulateCurAddrDefaultCfg()
        if self.curMenu=="wildcard_to_emulator_memory_address": self.idaDiscover.WildcardToEmulatorMemoryAddress()
        if self.curMenu=="wildcard_to_emulator_register": self.idaDiscover.WildcardToEmulatorRegister()
        if self.curMenu=="emulation_verbose_output": self.idaDiscover.AskEmuVerboseOutput()
        if self.curMenu=="show_current_emulation_config": self.idaDiscover.ShowCurrentEmulationConfig()
        if self.curMenu=="emulate_curaddr_default_cfg_and_wildcard": self.idaDiscover.EmulateCurAddrDefaultCfgAndWildcard()
        if self.curMenu=="set_emulator_results2comments": self.idaDiscover.SetEmulatorResults2Comments()
        if self.curMenu=="set_candidate_api_for_dwords": self.idaDiscover.SetCandidateApiForDwords()
        if self.curMenu=="enter_value_to_emulator_memory_address": self.idaDiscover.EnterValueToEmulatorMemoryAddress()
        if self.curMenu=="introduce_wildcard_to_key1": self.idaDiscover.WildcardToKey1()
        if self.curMenu=="introduce_wildcard_to_key2": self.idaDiscover.WildcardToKey2()
        if self.curMenu=="introduce_wildcard_to_content1": self.idaDiscover.WildcardToContent1()
        if self.curMenu=="edit_emu_parameters_store": self.idaDiscover.EditEmuParametersStore()
        if self.curMenu=="show_current_selections": self.idaDiscover.ShowCurrentSelections()
        if self.curMenu=="edit_current_selections": self.idaDiscover.EditCurrentSelections()
        return

    def update(self, ctx):
        return IDAAPI_AST_ENABLE_ALWAYS

def DoRegisterAction(name, desc, id, idaDiscover): IDAAPI_register_action(IDAAPI_action_desc_t(name,desc,IDADiscoverMenu(id, idaDiscover),None))

def RegisterMenus(idaDiscover):

    #last parameter of DoRegisterAction is "depth", and depth is converted to the option in IDADiscoverMenu __init__

    DoRegisterAction("IDADiscoverConfig", "Config - Configuration", 1, idaDiscover)
    #DoRegisterAction("IDADiscoverInstall", "Installation", 2, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisFull", "Analysis - Full (Ctrl-Shift-Alt-A)", 3, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisYara", "Analysis - Yara", 4, idaDiscover)
    #DoRegisterAction("IDADiscoverAnalysisSignSrch", "Analysis - SignSrch", 5, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisLoops", "Analysis - Loops", 6, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisEncryptedText", "Analysis - Encrypted text", 7, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisHeuristicIdentificationAlgorithms", "Analysis - Structures heuristic identification", 8, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisMostUsedFunctions", "Analysis - Most used functions", 9, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisStackStrings", "Analysis - Stack strings", 10, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisStackStringsPermutedCode", "Analysis - Stack strings permuted code", 11, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisUpNameFunctions", "Analysis - Up name functions", 12, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisApiCrc32Usage", "Analysis - Apis crc32 usage", 13, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisResetUpNameFunctions", "Reset - Up-name functions", 14, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSelectKey1", "Select - Key 1 (Ctrl-Shift-Alt-K)", 15, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSelectKey2", "Select - Key 2", 16, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSelectContent1", "Select - Content 1 (Ctrl-Shift-Alt-C)", 17, idaDiscover)
    DoRegisterAction("IDADiscoverCalculateRc4", "Calculate - RC4", 18, idaDiscover)
    DoRegisterAction("IDADiscoverCalculateAesCbc", "Calculate - AES CBC", 19, idaDiscover)
    DoRegisterAction("IDADiscoverCalculateAesEcb", "Calculate - AES ECB", 20, idaDiscover)
    DoRegisterAction("IDADiscoverCalculateXor", "Calculate - Xor", 21, idaDiscover)
    DoRegisterAction("IDADiscoverCalculateMd5", "Calculate - Md5", 22, idaDiscover)
    DoRegisterAction("IDADiscoverCalculateSha256", "Calculate - Sha256", 23, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSelectKey1FromFile", "Select - Key 1 from file", 24, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSelectKey2FromFile", "Select - Key 2 from file", 25, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSelectContent1FromFile", "Select - Content 1 from file", 26, idaDiscover)
    #DoRegisterAction("IDADiscoverRemoveYaraConflicts", "Remove Yara Rules Conflicts", 27, idaDiscover)
    #DoRegisterAction("IDADiscoverReloadYaraRules", "Reload Yara Rules", 28, idaDiscover)
    #DoRegisterAction("IDADiscoverReloadModules", "Reload Modules", 29, idaDiscover)
    DoRegisterAction("IDADiscoverConfigCallTargets", "Config - Call targets", 30, idaDiscover)
    DoRegisterAction("IDADiscoverConfigApiNames", "Config - Api names", 31, idaDiscover)
    DoRegisterAction("IDADiscoverConfigEncryptedTexts", "Config - Encrypted texts", 32, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSelectKey1FromAskRange", "Select - Key 1 from ask range", 33, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSelectKey2FromAskRange", "Select - Key 2 from ask range", 34, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSelectContent1FromAskRange", "Select - Content 1 from ask range", 35, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSelectSearchBlockSize1FromAskSize", "Select - Search block size 1", 36, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSelectStringAcceptHexa1FromAskString", "Select - String (Accept hexa)", 37, idaDiscover)
    DoRegisterAction("IDADiscoverSearchEncryptedStringRC4", "Search - String encrypted with Rc4", 38, idaDiscover)
    DoRegisterAction("IDADiscoverSearchEncryptedStringAESCBC", "Search - String encrypted with Aes Cbc", 39, idaDiscover)
    DoRegisterAction("IDADiscoverSearchEncryptedStringAESECB", "Search - String encrypted with Aes Ecb", 40, idaDiscover)
    DoRegisterAction("IDADiscoverSearchEncryptedStringXOR", "Search - String Encrypted with Xor", 41, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSelectKey1FromAskString", "Select - Key 1 from ask string (Ctrl-Shift-Alt-P)", 42, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSelectKey2FromAskString", "Select - Key 2 from ask string", 43, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSelectContent1FromAskString", "Select - Content 1 from ask string (Ctrl-Shift-Alt-S)", 44, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisCreateFunctionsForUnreferencedCodeBlocks", "Create - Functions for unreferenced code blocks", 45, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisContent1ToEmuMemAddr", "Emulator - Content1 to emu memory address", 46, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisEnterValueToRegister", "Emulator - DWORD to register", 47, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSetEmulationStartAddress", "Emulator - Set start address", 48, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSetEmulationEndAddress", "Emulator - Set end address", 49, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSetOutputRegister", "Emulator - Set register to recover (results after emulation)", 50, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSetOutputMemoryAddress", "Emulator - Set memory address to recover (results after emulation)", 51, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSetMapMemInvalid", "Emulator - Set flag: map invalid addresses on access violation?", 52, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSetMapFullCode", "Emulator - Set flag: map full ida segments code in emulator address space?", 53, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisResetEmu", "Emulator - Reset emulation config", 54, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisStartEmulation", "Emulator - Start emulation", 55, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSetEmulatorDebugMode", "Emulator - Set flag: enable debug mode?", 56, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSelectContent1Zeroes", "Select - Set zeros to Content 1", 57, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisInitEmulatorStack", "Emulator - Init emulator stack", 58, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSetInstructionToSkip", "Emulator - Add types of instruction to skip", 59, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSetMaxInsToEmulate", "Emulator - Set maximum number of instructions to emulate (default 1000)", 60, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisEmulateCurAddrDefaultCfg", "Emulator - Emulate from current address with default config (Ctrl-Shift-Alt-E)", 61, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisEnterWildcardToEmuMemAddr", "Emulator - Introduce wildcard to emulator memory address", 62, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisEnterWildcardToRegister", "Emulator - Introduce wildcard to emulator register", 63, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisVerboseOutputEmu", "Emulator - Set flag: enable verbose output?", 64, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSetRecommendedInstructionsToSkip", "Emulator - Add recommended instructions types to skip", 65, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisShowCurrentEmulationConfig", "Emulator - Show current emulation config", 66, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisEmulateCurAddrDefaultCfgWithWildcard", "Emulator - Emulate from wildcard matches with default cfg", 67, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSetEmulatorResults2IDAComments", "Emulator - Set flag: emulator results to IDA comments?", 68, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisSetCandidateApiForDwords", "Search - Set candidate Windows api for dwords", 69, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisEnterValueToMemoryAddress", "Emulator - DWORD to emu memory address", 70, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisWildcardToKey1", "Select - Introduce wildcard to key1", 71, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisWildcardToKey2", "Select - Introduce wildcard to key2", 72, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisWildcardToContent1", "Select - Introduce wildcard to content1", 73, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisEditEmuParametersStore", "Emulator - Edit emulation config", 74, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisShowCurrentSelections", "Select - Show Current Selections", 75, idaDiscover)
    DoRegisterAction("IDADiscoverAnalysisEditCurrentSelections", "Select - Edit Current Selections", 76, idaDiscover)

    IDAAPI_attach_action_to_menu('Edit/Plugins/', "IDADiscover", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/', "Loops", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/', "Fuctions", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/', "Signatures", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/', "Crypto", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/', "Select", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/', "Config", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/', "IDADiscoverAnalysisFull", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Config/', "IDADiscoverConfig", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Config/', "IDADiscoverConfigCallTargets", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Config/', "IDADiscoverConfigApiNames", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Config/', "IDADiscoverConfigEncryptedTexts", IDAAPI_SETMENU_APP)
    #IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Config/', "IDADiscoverInstall", IDAAPI_SETMENU_APP)
    #IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Config/', "IDADiscoverRemoveYaraConflicts", IDAAPI_SETMENU_APP)
    #IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Config/', "IDADiscoverReloadYaraRules", IDAAPI_SETMENU_APP)
    #IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Config/', "IDADiscoverReloadModules", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Signatures/', "IDADiscoverAnalysisYara", IDAAPI_SETMENU_APP)
    #IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Signatures/', "IDADiscoverAnalysisSignSrch", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Signatures/', "IDADiscoverAnalysisApiCrc32Usage", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Crypto/', "IDADiscoverAnalysisEncryptedText", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Crypto/', "IDADiscoverAnalysisStackStrings", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Crypto/', "IDADiscoverAnalysisStackStringsPermutedCode", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Crypto/', "IDADiscoverCalculateRc4", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Crypto/', "IDADiscoverCalculateAesCbc", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Crypto/', "IDADiscoverCalculateAesEcb", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Crypto/', "IDADiscoverCalculateXor", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Crypto/', "IDADiscoverCalculateMd5", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Crypto/', "IDADiscoverCalculateSha256", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Crypto/', "IDADiscoverSearchEncryptedStringRC4", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Crypto/', "IDADiscoverSearchEncryptedStringAESCBC", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Crypto/', "IDADiscoverSearchEncryptedStringAESECB", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Crypto/', "IDADiscoverSearchEncryptedStringXOR", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Loops/', "IDADiscoverAnalysisLoops", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Functions/', "IDADiscoverAnalysisHeuristicIdentificationAlgorithms", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Functions/', "IDADiscoverAnalysisMostUsedFunctions", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Functions/', "IDADiscoverAnalysisUpNameFunctions", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Functions/', "IDADiscoverAnalysisResetUpNameFunctions", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Functions/', "IDADiscoverAnalysisCreateFunctionsForUnreferencedCodeBlocks", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Functions/', "IDADiscoverAnalysisSetCandidateApiForDwords", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisSelectKey1", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisSelectKey2", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisSelectContent1", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisSelectKey1FromFile", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisSelectKey2FromFile", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisSelectContent1FromFile", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisSelectKey1FromAskRange", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisSelectKey2FromAskRange", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisSelectContent1FromAskRange", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisSelectSearchBlockSize1FromAskSize", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisSelectStringAcceptHexa1FromAskString", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisSelectKey1FromAskString", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisSelectKey2FromAskString", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisSelectContent1FromAskString", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisSelectContent1Zeroes", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisWildcardToKey1", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisWildcardToKey2", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisWildcardToContent1", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisShowCurrentSelections", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Select/', "IDADiscoverAnalysisEditCurrentSelections", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisEmulateCurAddrDefaultCfg", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisEmulateCurAddrDefaultCfgWithWildcard", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisContent1ToEmuMemAddr", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisEnterValueToMemoryAddress", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisEnterValueToRegister", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisEnterWildcardToEmuMemAddr", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisEnterWildcardToRegister", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisSetEmulationStartAddress", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisSetEmulationEndAddress", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisSetOutputRegister", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisSetOutputMemoryAddress", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisSetInstructionToSkip", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisSetRecommendedInstructionsToSkip", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisSetMapMemInvalid", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisSetMapFullCode", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisSetEmulatorDebugMode", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisSetMaxInsToEmulate", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisSetEmulatorResults2IDAComments", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisInitEmulatorStack", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisResetEmu", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisVerboseOutputEmu", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisStartEmulation", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisShowCurrentEmulationConfig", IDAAPI_SETMENU_APP)
    IDAAPI_attach_action_to_menu('Edit/Plugins/IDADiscover/Emu/'   , "IDADiscoverAnalysisEditEmuParametersStore", IDAAPI_SETMENU_APP)

idaDiscoverForHotkeys = None

def RegisterHotkeyAnalysisFull():
    global idaDiscoverForHotkeys
    idaDiscoverForHotkeys.FullAnalysis()

def RegisterHotkeySelectContent1():
    global idaDiscoverForHotkeys
    idaDiscoverForHotkeys.SelectContent1()

def RegisterHotkeySelectContent1FromAskString():
    global idaDiscoverForHotkeys
    idaDiscoverForHotkeys.SelectContent1FromAskString()

def RegisterHotkeySelectKey1():
    global idaDiscoverForHotkeys
    idaDiscoverForHotkeys.SelectKey1()

def RegisterHotkeySelectKey1FromAskString():
    global idaDiscoverForHotkeys
    idaDiscoverForHotkeys.SelectKey1FromAskString()

def RegisterHotkeyEmulateFromCurrentAddressWithDefaultCfg():
    global idaDiscoverForHotkeys
    idaDiscoverForHotkeys.EmulateCurAddrDefaultCfg()

def RegisterHotkeys(idaDiscover):
    global idaDiscoverForHotkeys
    idaDiscoverForHotkeys = idaDiscover
    IDAAPI_CompileLine('static key_ctrl_alt_a() { auto s = RunPythonStatement("RegisterHotkeyAnalysisFull()"); Message(s); }')
    IDAAPI_AddHotkey("Ctrl-Shift-Alt-A", 'key_ctrl_alt_a')
    IDAAPI_CompileLine('static key_ctrl_alt_c() { auto s = RunPythonStatement("RegisterHotkeySelectContent1()"); Message(s); }')
    IDAAPI_AddHotkey("Ctrl-Shift-Alt-C", 'key_ctrl_alt_c')
    IDAAPI_CompileLine('static key_ctrl_alt_s() { auto s = RunPythonStatement("RegisterHotkeySelectContent1FromAskString()"); Message(s); }')
    IDAAPI_AddHotkey("Ctrl-Shift-Alt-S", 'key_ctrl_alt_s')
    IDAAPI_CompileLine('static key_ctrl_alt_k() { auto s = RunPythonStatement("RegisterHotkeySelectKey1()"); Message(s); }')
    IDAAPI_AddHotkey("Ctrl-Shift-Alt-K", 'key_ctrl_alt_k')
    IDAAPI_CompileLine('static key_ctrl_alt_p() { auto s = RunPythonStatement("RegisterHotkeySelectKey1FromAskString()"); Message(s); }')
    IDAAPI_AddHotkey("Ctrl-Shift-Alt-P", 'key_ctrl_alt_p')
    IDAAPI_CompileLine('static key_ctrl_alt_e() { auto s = RunPythonStatement("RegisterHotkeyEmulateFromCurrentAddressWithDefaultCfg()"); Message(s); }')
    IDAAPI_AddHotkey("Ctrl-Shift-Alt-E", 'key_ctrl_alt_e')
