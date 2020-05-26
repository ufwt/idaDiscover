
f = open("signsrch.sig", "rb")
s = f.read()
f.close()
f = open("signsrch_clean.bin", "wb")
f.close()

l = s.split("################################################################################\r\n")


for e in l[1:-1]:    
    title = e.split("TITLE\r\n")[1].split("TYPE\r\n")[0].strip()
    datatype = e.split("TYPE\r\n")[1].split("DATA\r\n")[0].strip()
    data = e.split("DATA\r\n")[1]    
    l = data.split("\r\n")
    
    print title
    
    data += "  "
    data = data.replace("\\x", "0x")
    
    dataclean = ""
    
    waitcr = 0
    for i in range(0, len(data)-2):
        
        if waitcr and not (data[i]=="\r" and data[i+1]=="\n"):
            continue
        
        waitcr=0
        
        if (data[i]=="/" and data[i+1]=="/") or (data[i]=="/" and data[i+1]=="*") or data[i]=="#" or data[i]==";":
            waitcr=1
            continue
        
        if data[i]=="\"" or data[i]=="," or data[i]=="{" or data[i]=="}":
            dataclean += " "
            continue
            
        dataclean += data[i]
    
    dataclean = dataclean.replace("\r\n", " ")
    
    while 1:
        try:
            dataclean.index("  ")            
        except:
            break
        dataclean = dataclean.replace("  ", " ")
    
    f = open("signsrch_clean.bin", "a+b")
    f.write(title+"\r\n")
    f.write(datatype+"\r\n")
    f.write(dataclean+"\r\n")
    f.write("----\r\n")
    f.close()
            

