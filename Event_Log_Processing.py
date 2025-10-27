"""This program scans the Windows Event Logs of a Windows server to analyze for security events. Logs must be exported in csv format.
The program can perform the following functionality: 
1. Scan for all users that logged into the domain
2. Given a username, look for the IP Addresses and Workstations where that user has logged in from
3. Search for any user accounts that may have been compromised by a bruteforce attack

Author: Ronald Li (ronald.li.121206@gmail.com)"""
import os, re, sys, csv, time

#look for csv files in current directory
#argument: none
#return: list of csv files
def find_csv_files():
    found_csv_files = []
    files_in_directory = os.listdir(os.getcwd())
    pattern = r'.csv$'
    for file in files_in_directory:
        if re.search(pattern,file):
            found_csv_files.append(file)
        
    return found_csv_files

#get csv file selection
#argument: list of csv files
#return: path to csv file
def choose_csv(csv_files):
    print("Searching for csv files in the directory...")
    if len(csv_files) == 0:
        print("No csv files found.")
    #display user options
    print("Select one of the options below to scan:")
    counter = 1
    for file in csv_files:
        print (counter,":",file)
        counter += 1
    print(len(csv_files)+1,": Enter a file path to the csv file")
    print(len(csv_files)+2,": Exit the program")

    #accept user input and set the csv file to scan
    user_input = input()
    if int(user_input) <= len(csv_files):
        file_path = csv_files[int(user_input)-1]
    if int(user_input) == len(csv_files)+1:
        while True:
            file_path = input("Enter the file path to the csv file you want to scan or type 'exit' to quit")
            if file_path == 'exit':
                sys.exit()
            pattern = r'.csv$' #check that it's a csv
            if re.search(pattern,file_path):
                if os.path.exists(file_path):
                    print("File found.")
                    break
                else:
                    print("File not found. Enter the full path of the csv file or type 'exit' to quit")        
            else:
                print("File must be in csv format")
    if int(user_input) == len(csv_files)+2:
        sys.exit()

    return file_path

#find_users: retrieving all users that have logged into the domain
#argument: path to csv file
#return: none
def find_users(file_path):
    with open(file_path,'r') as file:
        data = list(csv.reader(file))

    set_of_users = set()
    for i in data: #iterates through each line of the file
        if i[3] == '4624': #successful logon event
            info = i[5] #isolate the text block with data
            info_split = info.split() #split the text block into each word
            for j in range(len(info_split)): #get the numerical range for each word to check each word
                if info_split[j] == "Security" and info_split[j+1] == "ID:":
                    name = info_split[j+2]
                    if re.search(r"^FDM1",name) and not re.search(r"WIN",name): #returning just the user accounts, removing any SYSTEM accounts and computer accounts (FDM1\WIN-....)
                        set_of_users.add(name)
    print("The list of users are:",set_of_users)

#find_workstation_and_ip: retrieving all users that have logged into the domain
#argument: path to csv file
#return: none
def find_workstation_and_ip(file_path):
    with open(file_path,'r') as file:
        data = list(csv.reader(file))

    count = 0 
    set_of_login_times = set() #store the time when the user logs in
    set_of_ip_address = set()
    user_name = input("Enter the username to search. Note backslashes need to be escaped. eg: FDM1\\\\marie :")

    #look for each time user shows up in a succesful log in, also storing the ip address and the log time of each entry
    for i in data: #iterates through each line of the file
        if i[3] == '4624': #successful logon event
            info = i[5] 
            info_split = info.split() 
            for j in range(len(info_split)): 
                if info_split[j] == "Security" and info_split[j+1] == "ID:":
                    name = info_split[j+2]
                    if re.search(user_name,name):
                        time = i[1]
                        set_of_login_times.add(time)
                        # print(count, time, name)

                        # extracting the ip address
                        for k in range(len(info_split)):
                            if info_split[k] == "Source" and info_split[k+1] == "Network" and info_split[k+2] == "Address:":
                                # print(info_split[k+3])
                                set_of_ip_address.add(info_split[k+3])
        count += 1

    #validating the ip addresses and moving invalid entries
    def ip_address_validate(input):
        octals = input.split(".")
        result = True
        if len(octals) != 4:
            result = False
        for i in octals:
            if i.isdigit():
                i = int(i)
                if i < 0 or i > 255:
                    result = False
            else:
                result = False
        return result

    list_of_ip_address = list(set_of_ip_address)
    for i in list_of_ip_address:
        if ip_address_validate(i):
            pass
        else:
            list_of_ip_address.remove(i)
    print(f"The list of ip addresses that {user_name} has logged in from:",list_of_ip_address)
        

    #getting the workstation
    # print(set_of_login_times)
    list_of_login_times = list(set_of_login_times)
    set_of_workstations = set()

    for i in data:
        for j in list_of_login_times:
            if i[1] == j:
                info = i[5] 
                info_split = info.split() 
                for k in range(len(info_split)):
                    if re.search(r"WIN-",info_split[k]):
                        # print(info_split[k])
                        set_of_workstations.add(info_split[k]) #adding to a set will automatically remove duplicates

    # print(set_of_workstations) # this is prior to validating the list of workstations
    list_of_workstations = list(set_of_workstations)
    for i in list_of_workstations:
        if re.search(r"FDM1\\",i):
            list_of_workstations.remove(i)
    print(f"The workstations that {user_name} has logged in from:",list_of_workstations)

#find_brute_force: detect if there's a user with a high number of failed login and then a successful login afterwards
#argument: path to csv file
#return: none
#Part 1: Show the time stamp of each failed login to these accounts.
#Part 2: Determine if the attacker managed to compromise the account with a successful login.
def find_brute_force(file_path):
    with open(file_path,'r') as file:
        data = list(csv.reader(file))
    
    set_of_users_failed_logins = set() #generate a set of usernames that have failed logins
    failed_login_data = {} #dictionary of each user with failed logins, with the usernames as keys and list of their failed login times as values
    for i in data:
        if i[3] == '4771': #failed login Event ID
            info = i[5]
            info_split = info.split()
            for j in range(len(info_split)):
                if info_split[j] == "Security" and info_split[j+1] == "ID:":
                    name = info_split[j+2]
                    if re.search(r"^FDM1",name) and not re.search(r"WIN",name): 
                        #check if this user already has a failed login, if the user doesn't: add the name to the dictionary and the time of failed login, otherwise: only add the time
                        if name in set_of_users_failed_logins:
                            pass
                        else:
                            set_of_users_failed_logins.add(name)
                            failed_login_data[name] = [] #initialize a list
                        failed_login_data[name].append(i[1]) #add the timestamp of the failed login
    
    print("\nList of users and their failed login times:")
    print(failed_login_data)
    time.sleep(1)
    print("\nChecking if any users with more than 3 failed attempts had a successful login afterwards")

    #check if there is a successful login after the brute force attack
    for i in set_of_users_failed_logins:
        if len(failed_login_data[i]) >= 3:

            list_of_successful_logins = []
            for j in data:
                if j[3] == '4624':
                    info = j[5]
                    info_split = info.split()
                    for k in range(len(info_split)):
                        if info_split[k] == "Security" and info_split[k+1] == "ID:":
                            name = info_split[k+2]
                            if i == name: 
                                list_of_successful_logins.append(j[1])
            list_of_successful_logins = sorted(list_of_successful_logins) #sorted by oldest to newest
            print("Successful logins for",i,list_of_successful_logins)
            time.sleep(1)

        #sorting the data to determine if the attacker logined after the failed attempts
        attacked = False #track if the attacker logged in after three failed attempts
        failed_logins_sorted = sorted(failed_login_data[i], reverse=True) 
        for j in list_of_successful_logins:
            if j > failed_logins_sorted[-3]: #checking if the successful login happened after the 3rd oldest failed login
                attacked = True
                print("\nSince a successful login was logged at",j,"after three failed login attempts, a successful attack was likely and should be investigated.")
                break
        if attacked == False:
            print("\nThe attacker last attempted to login at",failed_login_data[0],"no successful logins were detected aftewards. The attack was unsuccessful.")

#MAIN
print("This script analyzes the Windows Event Logs of a Domain Controller.\nLogs need to be provided to the script in csv format.\n...")
#find csv file to scan
csv_files = find_csv_files()
#get user's choice for csv file to scan
chosen_csv = choose_csv(csv_files)
print("\nProceeding to scan:",chosen_csv)

#select and run one of the functionalities
while True:
    time.sleep(1)
    print("""\nSelect one of the following functionalities:
    1. Scan for all users that logged into the domain
    2. Given a username, look for the IP Addresses and Workstations where that user has logged in from
    3. Search for any user accounts that may have been compromised by a bruteforce attack
    4. Exit""")
    user_input = input()
    if user_input == '1':
        find_users(chosen_csv)
    elif user_input == '2':
        find_workstation_and_ip(chosen_csv)
    elif user_input == '3':
        find_brute_force(chosen_csv)
    elif user_input == '4':
        sys.exit()
    else:
        print("Invalid input.")