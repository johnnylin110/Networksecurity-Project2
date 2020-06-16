# Scan wireshark file and get all ip.dst value.
# Please set the train_num_person and test_num_person as numbers of training data and testing data. 
import json
train_num_person = 6
test_num_person = 2
def deep_search(needles, haystack):
    if type(needles) != type([]):
        needles = [needles]

    if type(haystack) == type(dict()):
        for needle in needles:
            if needle in haystack.keys():
                found.append([haystack[needle]]) 
            if len(haystack.keys()) > 0:
                for key in haystack.keys():
                    deep_search(needle, haystack[key])
    elif type(haystack) == type([]):
        for node in haystack:
            deep_search(needles, node)

# Training data
for i in range(1,train_num_person+1):
    print('Processing training data: ', i)
    with open('./Logs/Train/Person_' + str(i) + '/Wireshark.json',encoding="utf8", errors='ignore') as json_file:
        data = json.load(json_file)
    found = []
    deep_search(['ip.dst'], data)
    with open('./Logs/Train/Person_' + str(i) + '/Person_'+ str(i) + '_IP.txt', 'w') as filehandle:
        for listitem in found:
            filehandle.write('%s\n' % listitem[0])

# Testing data
for i in range(1,test_num_person+1):
    print('Processing testing data: ', i)
    with open('./Logs/Example Test/Test_' + str(i) + '/Wireshark.json',encoding="utf8", errors='ignore') as json_file:
        data = json.load(json_file)
    found = []
    deep_search(['ip.dst'], data)
    with open('./Logs/Example Test/Test_' + str(i) + '/Test_Person_'+ str(i) + '_IP.txt', 'w') as filehandle:
        for listitem in found:
            filehandle.write('%s\n' % listitem[0])


# Read file contant IPs as list
# Person_IP = []
# with open('./Logs/Person_1_IP.txt', 'r') as filehandle:
#     for line in filehandle:
#         currentPlace = line[:-1]
#         Person_IP.append(currentPlace)