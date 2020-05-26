import os
import zipfile
import ConfigParser
import shutil
import sys
import urllib3
import ssl
from utils import Utils

class Installation():

    ################################################################################################        
    @staticmethod
    def doInstall():
        print("Do install")
        scriptpath = os.path.abspath(os.path.dirname(__file__))
        #pythonpath = os.path.abspath(os.path.dirname(sys.executable))
        #shutil.copyfile("%s/stdint.h_" % scriptpath, "%s/include/stdint.h" % pythonpath)
        #shutil.copyfile("%s/libeay32.lib_" % scriptpath, "%s/libs/libeay32.lib" % pythonpath)
        print("Install future if it is not already installed")
        Installation.import_or_install("future", "future")
        print("Install yara-python if it is not already installed")
        Installation.import_or_install("yara", "yara-python")
        print("Install py_aho_corasick if it is not already installed")
        Installation.import_or_install("py_aho_corasick", "py_aho_corasick")
        print("Install pycrypto if it is not already installed")
        Installation.import_or_install("Crypto", "pycrypto")
        print("Install unicorn if it is not already installed")
        Installation.import_or_install("unicorn", "unicorn")
        print("Install capstone if it is not already installed")
        Installation.import_or_install("capstone", "capstone")
        #some yara rules cause conflicts with python yara version. If we have updated yara rules, we will try to compile them, 
        #removing conflicting rules until they compile with no error
        print("Remove yara rules conflicts")
        Installation.remove_yara_rules_conflict()

    ################################################################################################        
    @staticmethod
    def import_or_install(importname, packagename):
        pipmod = None
        try:
            temp = __import__(importname)
            return
        except ImportError:
            print("Error! Unable to import %s. Trying to install it" % importname)
        try:
            pipmod = __import__("pip")
        except:
            print("Error! Unable to import pip, please install pip")
            return
        try:
            pipmod.main(['install', packagename])
        except:
            print("Error! Pip was found but it was impossible to install %s" % packagename)

    ################################################################################################
    @staticmethod
    def download_master_and_unzip(url):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        scriptpath = os.path.abspath(os.path.dirname(__file__))
        http = urllib3.PoolManager()
        response = http.request('GET', url)
        content = response.data
        f = open(scriptpath+"/master.zip", "wb")
        f.write(content)
        f.close()
        zip_ref = zipfile.ZipFile(scriptpath+"/master.zip", "r")
        zip_ref.extractall(scriptpath)
        zip_ref.close()
        os.remove(scriptpath+"/master.zip")
        
    ################################################################################################        
    
    @staticmethod
    def _incl_callback(requested_filename, filename, namespace):
        return open(requested_filename,"rb").read()
    
    ################################################################################################        
    
    @staticmethod
    def remove_yara_rules_conflict():
        nconflicts=0
        yaramod = __import__("yara")
        config = ConfigParser.RawConfigParser()
        config.read(Utils.GetIniFilePath())
        yaraRulesPath = config.get("run", "genconfig_yaraRulesPath").replace("%~dp0", os.path.dirname(os.path.realpath(__file__)))
        yaraRulesPathDirectory = os.path.dirname(os.path.realpath(yaraRulesPath))
        curDirectory = os.getcwd()
        os.chdir(yaraRulesPathDirectory)
        while 1:
            try:
                yaramod.compile(yaraRulesPath, includes=True, include_callback=Installation._incl_callback)
                break
            except Exception as e:
                print(repr(e))
                conflict = ""
                if "can't open include file: " in repr(e): conflict = repr(e).split("can't open include file: ")[1]
                elif "('" in repr(e): conflict = repr(e).split("('")[1].split("(")[0]
                else: conflict = repr(e).split("(")[0]
                if not len(conflict) or not ".yar" in conflict:
                    if ".yar(" in repr(e) and "\"./" in repr(e): conflict = "./"+repr(e).split(".yar(")[0].split("\"./")[1] + ".yar"
                    if ".yara(" in repr(e) and "\"./" in repr(e): conflict = "./"+repr(e).split(".yara(")[0].split("\"./")[1] + ".yara"
                if len(conflict)>=2 and conflict[0:2] == "./": conflict = yaraRulesPathDirectory + "/" + conflict[2:]
                if ".yar\",)" in conflict: conflict = conflict.replace(".yar\",)", ".yar")
                if ".yara\",)" in conflict: conflict = conflict.replace(".yara\",)", ".yara")
                print("Conflict with: %s" % conflict)
                f = open(conflict, "wb")
                f.close()
                nconflicts+=1
                if nconflicts==10000:
                    print("too much conflicts compiling yara rules!!! leaving")
                    break
        os.chdir(curDirectory)
