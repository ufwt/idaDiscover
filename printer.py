from ida_defines import *
import tempfile

####################################################################################################

class InternalPrinter(simplecustviewer_t):
    
    ################################################################################################
    def __init__(self, name):
        self.name = name
        self.tmpdir = tempfile.gettempdir()
    
    ################################################################################################
    def Start(self):
        self.Create(self.name)

    ################################################################################################
    def doPrint(self, s):
        print(s)
        f = open(self.tmpdir + "/idadiscover.log", "a+b")
        f.write(self.name + ":" + s + "\r\n")
        f.close()
        self.AddLine(s)
        self.Show()

    ################################################################################################
    def Create(self, sn=None):
        print("Create")
        print(sn)
        if not IDAAPI_simplecustviewer_t.Create(self, sn):
            return False
        return True

    ################################################################################################
    def Clear(self):
        self.ClearLines()
    
    ################################################################################################
    def jmpto(self, target):
        try:jumpto(IDAAPI_ItemHead(int(target, 16)))
        except:pass
        try:jumpto(IDAAPI_LocByName(target))
        except:pass

    ################################################################################################
    def OnDblClick(self, shift):
        self.jmpto(self.GetCurrentWord())
        
    ################################################################################################
    def OnKeydown(self, vkey, shift):
        self.jmpto(self.GetCurrentWord())
        
    ################################################################################################
    def OnPopupMenu(self, menu_id):
        print("OnPopupMenu")

####################################################################################################




####################################################################################################

class Printer():

    ################################################################################################
    def __init__(self):
        self.Printers = dict()
        self.Printers["algorithms"] = InternalPrinter("Algorithms - IDA Discover results")
        self.Printers["crypto"] = InternalPrinter("Crypto - IDA Discover results")
        self.Printers["emulator"] = InternalPrinter("Emulator - IDA Discover results")
        self.Printers["loops"] = InternalPrinter("Loops - IDA Discover results")
        self.Printers["references"] = InternalPrinter("References - IDA Discover results")
        self.Printers["signsrch"] = InternalPrinter("Signsrch - IDA Discover results")
        self.Printers["functions"] = InternalPrinter("Functions - IDA Discover results")
        self.Printers["yara"] = InternalPrinter("Yara - IDA Discover results")
        self.Printers["general"] = InternalPrinter("General - IDA Discover results")
    
    ################################################################################################
    def Start(self):
        for e in self.Printers.keys():
            self.Printers[e].Start()

    ################################################################################################
    def doPrint(self, s, origin="general"):
        self.Printers[origin].doPrint(s)
    
    ################################################################################################
    def Clear(self, name=None):
        if name:
            self.Printers[name].Clear()
        else:
            for e in self.Printers.keys():
                self.Printers[e].Clear()       

####################################################################################################
