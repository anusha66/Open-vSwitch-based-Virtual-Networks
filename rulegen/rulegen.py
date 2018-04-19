import os,sys

if sys.argv[1]:
  urlFileList = open(sys.argv[1]).readlines()
  urlFileList = map(lambda r: r.strip(), urlFileList)
else:
  print "Please enter the path to the URL file and name of the URL file after the command"
  
path = sys.argv[1][sys.argv[1].rfind("\\")+1:sys.argv[1].rfind(".")]

#Snort rules require hex numbers in 1-byte blocks. Python doesn't always like to provide them that way
def zeropadding(hexaNum):
  if len(hexaNum) % 2 == 1:
    return "0" + str(hexaNum)[2:]
  return hexaNum[2:]
 
  
def generateDnsRules(urlFileList):
  hosts = [i[:i.index("/")] if "/" in i else i for i in urlFileList]
  eliminatePath = [i.split("/")[0] for i in urlFileList]
  urlSplit = [i.split(".") for i in eliminatePath]
  urlMash = [["|" + zeropadding(hex(len(i))) + "|" + i for i in y] for y in urlSplit]
  urlDnsFormat = ["".join(i) for i in urlMash]
  urlFinal = zip(urlDnsFormat,hosts)
  snortRule = ['alert udp $HOME_NET any -> any 53 (msg:"' + path + ' dns request for root location ' + i[1] + '"; byte_test:1,!&,0xF8,2; content:"' + i[0] + '|00|";)\n' for i in urlFinal]
  return snortRule
  
rulesFile = open("/home/student/rulegen/rules.txt","w")
for rule in generateDnsRules(urlFileList):
  rulesFile.write(rule)
rulesFile.close()
  
def generateHttpRules(urlFileList):
  hostSplit = [i[:i.index("/")] if "/" in i else i for i in urlFileList]
  uriSplit = [i[i.index("/"):] if "/" in i else '' for i in urlFileList]
  hostContentRuleSection = ['content:"Host: ' + i + '"; http_header; ' for i in hostSplit]
  uriContentRuleSection = ['content:"' + i + '"; http_uri; ' if len(i) > 1 else "" for i in uriSplit]
  snortRule = []
  for rule in zip(hostContentRuleSection, uriContentRuleSection, urlFileList):
    if rule[1] == 0:
      snortRule.append('alert tcp $HOME_NET any -> any $HTTP_PORTS (msg:"' + path + ' HTTP trying to access ' + rule[2] + '";' + str(rule[0]) + ')\n')
    else:
      snortRule.append('alert tcp $HOME_NET any -> any $HTTP_PORTS (msg:"' + path + ' HTTP trying to access ' + rule[2] + '";' + str(rule[0]) + str(rule[1]) + ')\n')
  return snortRule
  

rulesFile = open("/home/student/rulegen/rules.txt","a") 
for rule in generateHttpRules(urlFileList):
  rulesFile.write(rule)
rulesFile.close()
