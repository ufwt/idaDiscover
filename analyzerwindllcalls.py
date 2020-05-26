from ida_defines import *
from utils import Utils
import os
import pefile

class AnalyzerWindllCalls():

####################################################################################################

	################################################################################################

	def __init__(self, gPrinter):
		self.gPrinter = gPrinter
		self.windlls = dict()
		self.windllsLoaded = False

	################################################################################################

	def LoadSampleDllsExportsRVAs(self):
		owndir = os.path.dirname(os.path.realpath(__file__))
		for subdir in os.listdir("%s/WinDlls" % owndir):
			#self.windlls[subdir] = dict()
			for dllname in os.listdir("%s/WinDlls/%s" % (owndir, subdir)):
				s = open("%s/WinDlls/%s/%s" % (owndir, subdir, dllname), "rb").read(0x5000)
				dll = pefile.PE(data=s)
				if not hasattr(dll, "DIRECTORY_ENTRY_EXPORT"):
					dll = pefile.PE("%s/WinDlls/%s/%s" % (owndir, subdir, dllname))
				for exp in dll.DIRECTORY_ENTRY_EXPORT.symbols:
					if exp.name:
						if exp.address&0xffff not in self.windlls: self.windlls[exp.address&0xffff] = list()
						self.windlls[exp.address&0xffff].append({"winver": subdir, "dllname" : dllname, "export" : exp.name.decode('utf-8')})
		self.windllsLoaded = True
		
	################################################################################################
	
	def SetDwordsCandidateApi(self):
		if not self.windllsLoaded: self.LoadSampleDllsExportsRVAs()
		names = Utils.GetIDANames(bNoCode=True)
		for name in names:
			if "dword" in name[1]:
				ptr = struct.unpack("<L", IDAAPI_GetManyBytes(name[0],4))[0]
				if ptr < 0x80000000:
					print "%x %x" % (name[0], ptr)
					ptrlow = ptr & 0xffff
					if ptrlow in self.windlls.keys():
						print "match"
						cmt = ""
						for export in self.windlls[ptrlow]: cmt += "%s %s %s\r\n" % (repr(export["winver"])[1:-1], repr(export["dllname"])[1:-1], repr(export["export"])[2:-1])
						print cmt
						IDAAPI_MakeRptCmt(name[0], cmt)
						if len(self.windlls[ptrlow])==1:
							IDAAPI_MakeNameEx(name[0], "%s_%s" % (repr(export["dllname"])[1:-1], repr(export["export"])[2:-1]), IDAAPI_SN_CHECK|IDAAPI_SN_NOWARN)

	################################################################################################
				

if __name__ == "__main__":
	awc = AnalyzerWindllCalls(None)
	awc.LoadSampleDllsExportsRVAs()
	recursive_print(awc.windlls)
