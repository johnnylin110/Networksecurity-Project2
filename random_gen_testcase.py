# Random generate testcase from training dataset
import os
import random
sub_length = 0.2
if not os.path.isdir('./Logs/Test') :
    os.mkdir('./Logs/Test')
for i in range(6):
    if not os.path.isdir('./Logs/Test/Test_' + str(i+1)) :
        os.mkdir('./Logs/Test/Test_' + str(i+1))
        
for i in range(6):
    with open('./Logs/Train/Person_' + str(i+1) + '/Sysmon.xml',encoding="utf-8") as f:
        sysmon_file=f.read()
    with open('./Logs/Train/Person_' + str(i+1) + '/Person_' + str(i+1) + '_IP.txt',encoding="utf-8") as f:
        ip_file=f.read()
    with open('./Logs/Train/Person_' + str(i+1) + '/Security.xml',encoding="utf-8") as f:
        security_file=f.read()

    fp = open('./Logs/Test/Test_' + str(i+1) + '/Sysmon.xml', "w", encoding="utf-8")
    random_start = random.randint(0,int(len(sysmon_file)*(1-sub_length))-1)
    fp.write(sysmon_file[random_start:random_start + int(len(sysmon_file)*sub_length)])
    fp.close()
    
    fp = open('./Logs/Test/Test_' + str(i+1) +  '/Test_Person_' + str(i+1) + '_IP.txt', "w", encoding="utf-8")
    random_start = random.randint(0,int(len(ip_file)*(1-sub_length))-1)
    fp.write(ip_file[random_start:random_start + int(len(ip_file)*sub_length)])
    fp.close()

    fp = open('./Logs/Test/Test_' + str(i+1) + '/Security.xml', "w", encoding="utf-8")
    random_start = random.randint(0,int(len(security_file)*(1-sub_length))-1)
    fp.write(security_file[random_start:random_start + int(len(security_file)*sub_length)])
    fp.close()