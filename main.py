import re
import numpy as np
exe_file_name = dict()
query_name = dict()
all_ip = dict()
Event_IDs = dict()
train_num_person = 6
test_num_person = 2
testing_num = 2
testing_dir = 'Example Test'

####################################
####################################
# Data Preprocessing 
####################################
####################################

# Count every ".exe file name" and "QuaryName" appear in Sysmon.xml as "exe_file_name" and "query_name" respectively.
for i in range(1,train_num_person+1):
    with open('./Logs/Train/Person_'+str(i)+'/Sysmon.xml',encoding="utf-8") as f:
        file=f.read()
        ans = [x.group() for x in re.finditer('([A-Z]|[a-z]|[0-9]|\+|\-|\_|[â-û])+' + '.exe' ,file)]
        for j in ans:
            exe_file_name[j] = 0.0
            
        ans = [x.group()[23: len(x.group())-7] for x in re.finditer("<Data Name='QueryName'>" + '([A-Z]|[a-z]|[0-9]|\+|\-|\_|\.|[â-û])+' + '</Data>' ,file)]
        for j in ans:
            query_name[j] = 0.0
        
for i in range(1,test_num_person+1):
    with open('./Logs/Example Test/Test_'+str(i)+'/Sysmon.xml',encoding="utf-8") as f:
        file=f.read()
        ans = [x.group() for x in re.finditer('([A-Z]|[a-z]|[0-9]|\+|\-|\_|[â-û])+' + '.exe',file)]
        for j in ans:
            exe_file_name[j] = 0.0
            
        ans = [x.group()[23: len(x.group())-7] for x in re.finditer("<Data Name='QueryName'>" + '([A-Z]|[a-z]|[0-9]|\+|\-|\_|\.|[â-û])+' + '</Data>' ,file)]
        for j in ans:
            query_name[j] = 0.0
            
# Count every "IP" appear in Person_{1,6}_IP.txt as "all_ip"
for i in range(1,train_num_person+1):
    with open('./Logs/Train/Person_' + str(i) + '/Person_' + str(i) + '_IP.txt', 'r') as filehandle:
        f=filehandle.read()
        ans = [x.group() for x in re.finditer('[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}',f)] # Get fisrt 3 value of IP.
        for j in ans:
            all_ip[j] = 0

for i in range(1,test_num_person+1):
    with open('./Logs/Example Test/Test_' + str(i) + '/Test_Person_' + str(i) + '_IP.txt', 'r') as filehandle:
        f=filehandle.read()
        ans = [x.group() for x in re.finditer('[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}',f)]
        for j in ans:
            all_ip[j] = 0

# Count every "EventID" appear in Security.xml as "Event_IDs"
for i in range(1,train_num_person+1):
    with open('./Logs/Train/Person_' + str(i) + '/Security.xml', 'r',encoding="utf-8") as filehandle:
        f=filehandle.read()
        ans = [x.group()[9: len(x.group())-10] for x in re.finditer('<EventID>' + '[0-9]+' + '</EventID>' ,f)]
        for j in ans:
            Event_IDs[j] = 0.0

for i in range(1,test_num_person+1):
    with open('./Logs/Example Test/Test_' + str(i) + '/Security.xml', 'r',encoding="utf-8") as filehandle:
        f=filehandle.read()
        ans = [x.group()[9: len(x.group())-10] for x in re.finditer('<EventID>' + '[0-9]+' + '</EventID>' ,f)]
        for j in ans:
            Event_IDs[j] = 0.0



####################################
####################################
# Compute User Information Vector
####################################
####################################

# Compute ".exe file" statistical vactor of every training data and testing data
train_total_count_exe = []           
for i in range(1,train_num_person+1):
    with open('./Logs/Train/Person_'+str(i)+'/Sysmon.xml',encoding="utf-8") as f:
        file=f.read()
        ans = [x.group() for x in re.finditer('([A-Z]|[a-z]|[0-9]|\+|\-|\_|[â-û])+' + '.exe',file)]
        temp = exe_file_name.copy()
        for j in ans:
            temp[j] += 1.0
        train_total_count_exe.append(list(temp.values()))
        for j in range(len(train_total_count_exe[i-1])):
            if len(ans) > 0 :
                train_total_count_exe[i-1][j] /= len(ans)
        
test_total_count_exe = []
for i in range(1,testing_num+1):
    with open('./Logs/' + testing_dir +'/Test_'+str(i)+'/Sysmon.xml',encoding="utf-8") as f:
        file=f.read()
        ans = [x.group() for x in re.finditer('([A-Z]|[a-z]|[0-9]|\+|\-|\_|[â-û])+' + '.exe',file)]
        temp = exe_file_name.copy()
        for j in ans:
            temp[j] += 1
        test_total_count_exe.append(list(temp.values()))
        for j in range(len(test_total_count_exe[i-1])):
            if len(ans) > 0 :
                test_total_count_exe[i-1][j] /= len(ans)

# Compute "QuaryName" statistical vactor of every training data and testing data
train_total_count_quaryname = []           
for i in range(1,train_num_person+1):
    with open('./Logs/Train/Person_'+str(i)+'/Sysmon.xml',encoding="utf-8") as f:
        file=f.read()
        ans = [x.group()[23: len(x.group())-7] for x in re.finditer("<Data Name='QueryName'>" + '([A-Z]|[a-z]|[0-9]|\+|\-|\_|\.|[â-û])+' + '</Data>' ,file)]
        temp = query_name.copy()
        for j in ans:
            temp[j] += 1.0
        train_total_count_quaryname.append(list(temp.values()))
        for j in range(len(train_total_count_quaryname[i-1])):
            if len(ans) > 0 :
                train_total_count_quaryname[i-1][j] /= len(ans)
        
test_total_count_quaryname = []
for i in range(1,testing_num+1):
    with open('./Logs/' + testing_dir +'/Test_'+str(i)+'/Sysmon.xml',encoding="utf-8") as f:
        file=f.read()
        ans = [x.group()[23: len(x.group())-7] for x in re.finditer("<Data Name='QueryName'>" + '([A-Z]|[a-z]|[0-9]|\+|\-|\_|\.|[â-û])+' + '</Data>' ,file)]
        temp = query_name.copy()
        for j in ans:
            temp[j] += 1
        test_total_count_quaryname.append(list(temp.values()))
        for j in range(len(test_total_count_quaryname[i-1])):
            if len(ans) > 0 :
                test_total_count_quaryname[i-1][j] /= len(ans)
            
# Compute "IP" statistical vactor of every training data and testing data
train_total_count_IP = []           
for i in range(1,train_num_person+1):
    with open('./Logs/Train/Person_' + str(i) + '/Person_' + str(i) + '_IP.txt', 'r') as filehandle:
        f=filehandle.read()
        ans = [x.group() for x in re.finditer('[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}',f)]
        temp = all_ip.copy()
        for j in ans:
            temp[j] += 1.0
        train_total_count_IP.append(list(temp.values()))
        for j in range(len(train_total_count_IP[i-1])):
            if len(ans) > 0 :
                train_total_count_IP[i-1][j] /= len(ans)
        
test_total_count_IP = []
for i in range(1,testing_num+1):
    with open('./Logs/' + testing_dir +'/Test_' + str(i) + '/Test_Person_'+str(i)+'_IP.txt', 'r') as filehandle:
        f=filehandle.read()
       
        ans = [x.group() for x in re.finditer('[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}',f)]
        temp = all_ip.copy()
        for j in ans[1:-1]:
            temp[j] += 1
        test_total_count_IP.append(list(temp.values()))
        for j in range(len(test_total_count_IP[i-1])):
            if len(ans) > 0 :
                test_total_count_IP[i-1][j] /= len(ans)

# Compute "EventID" statistical vactor of every training data and testing data
train_total_count_eventID = []           
for i in range(1,train_num_person+1):
    with open('./Logs/Train/Person_'+str(i)+'/Security.xml',encoding="utf-8") as f:
        file=f.read()
        ans = [x.group()[9: len(x.group())-10] for x in re.finditer('<EventID>' + '[0-9]+' + '</EventID>' ,file)]
        temp = Event_IDs.copy()
        for j in ans:
            temp[j] += 1.0
        train_total_count_eventID.append(list(temp.values()))
        for j in range(len(train_total_count_eventID[i-1])):
            if len(ans) > 0 :
                train_total_count_eventID[i-1][j] /= len(ans)
        
test_total_count_eventID = []
for i in range(1,testing_num+1):
    with open('./Logs/' + testing_dir +'/Test_'+str(i)+'/Security.xml',encoding="utf-8") as f:
        file=f.read()
        ans = [x.group()[9: len(x.group())-10] for x in re.finditer('<EventID>' + '[0-9]+' + '</EventID>' ,file)]
        temp = Event_IDs.copy()
        for j in ans:
            temp[j] += 1
        test_total_count_eventID.append(list(temp.values()))
        for j in range(len(test_total_count_eventID[i-1])):
            if len(ans) > 0 :
                test_total_count_eventID[i-1][j] /= len(ans)




####################################
####################################
# Compute L1-norm of (test vector - train vector)
####################################
####################################

# Compute norm of the vector = [testing_data - training_data]  
for i in range(testing_num):
    exe_result=[]
    IP_result=[]
    quary_result=[]
    eventID_result=[]
    final_result=[]
    for j in range(train_num_person):
        exe_result.append(np.linalg.norm(np.array(test_total_count_exe[i])-np.array(train_total_count_exe[j])))
        IP_result.append(np.linalg.norm(np.array(test_total_count_IP[i])-np.array(train_total_count_IP[j])))
        quary_result.append(np.linalg.norm(np.array(test_total_count_quaryname[i])-np.array(train_total_count_quaryname[j])))
        eventID_result.append(np.linalg.norm(np.array(test_total_count_eventID[i])-np.array(train_total_count_eventID[j])))    
        final_result.append(exe_result[j]*0.5+IP_result[j]*0.5+quary_result[j]*0.1+eventID_result[j]*0.01)
        # print(final_result[j])
    # print(exe_result,IP_result,quary_result,eventID_result)
    print("testcase " + str(i+1) +": person " + str(np.argmin(final_result)+1))