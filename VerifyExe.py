import py as py
import schedule
import time
import os
import psutil
import hashlib
import PEExtracter

from vt import APIError

import config
import vt

from twython import Twython, TwythonError

from FetchProcessID import FetchProcessID

p = FetchProcessID()
virusTotalAPI = Twython(config.api_key_VT)
client = vt.Client(virusTotalAPI.app_key)
processCurrentlyRunning = set()
test = "hello"

windows_services_parent_process = \
    {
        "wininit.exe": "smss.exe",
        "System": "",
        "services.exe": "wininit.exe",
        "lsass.exe": "wininit.exe",
        "taskhostw.exe": "svchost.exe",
        "svchost.exe": "services.exe",

    }
windows_services_path = \
    {
        "services.exe": "C:\\Windows\\System32\\services.exe",
        "svchost.exe": "C:\\Windows\\System32\\svchost.exe",
        "wininit.exe": "C:\\Windows\\System32\\wininit.exe",
        "explorer.exe": "C:\\Windows\\System32\\explorer.exe",
    }


def get_info_file(hash):
    file = client.get_object("/files/" + str(hash))
    return file


def scan_file(path):
    with open(path, "rb") as f:
        analysis = client.scan_file(f, wait_for_completion=True)
    return analysis


def CheckRunningProcess():
    print(("calling setlist 1"))
    time.sleep(5)
    print(("calling setlist 2"))
    p.processIDlist2 = p.getCurrentRunningProcessID()

    combinedList = p.processIDlist2.difference(p.processIDlist1)
    print(combinedList)

    p.processIDlist1 = p.processIDlist2

    for proc in combinedList:
        running_exe_dict = {}
        try:

        # should check process location and then parent process, if parent process doesnt exists it throws exception and continues
            process = psutil.Process(proc)
            checkProcessLocation(process)
            checkProcessParent(process)

            parentProcess = psutil.Process(process.ppid())
            checkProcessParent(parentProcess)
            checkProcessLocation(parentProcess)

        # print("current process")
        # process = psutil.Process(proc)
        # process_name = process.name()
        # print(process_name)
        # running_exe_dict[process.pid] = process.name()
        #
        # print("parent")
        # parentProcess = psutil.Process(process.ppid())
        # print(parentProcess)
        # print(parentProcess.exe())

        # print("looking at parent process")
        # if process_name in windows_services_parent_process.keys():
        #     print("hit")
        #     print(windows_services_parent_process[process_name])

        # print("grandparent")
        # grandparentProcess = psutil.Process(parentProcess.ppid())
        # print(grandparentProcess)
        # print(grandparentProcess.exe())
        #
        # if parentProcess.name() in windows_services_parent_process.keys():
        #     print("hit")
        #     print(windows_services_parent_process[parentProcess])

        # print(checkHash(process.exe()))

        except Exception as e:
            print(e)

    print(running_exe_dict)

    print("combined")
    print(combinedList)


# checks the process parent
def checkProcessParent(process):
    parentProcess = psutil.Process(process.ppid())

    if process.name() in windows_services_parent_process.keys():
        if parentProcess.name() == windows_services_parent_process[process.name()]:
            print(process.name() + " is verified")
            print("dictionary print:")
            print(windows_services_parent_process[process])
            return True
        else:
            print(process.name() + " parent is not verified")
           #virusTotalVerification(process)
    else:
        print(process.name() + " ignore process")
        process.kill()
        return False


def virusTotalVerification(process):
    try:
        report = get_info_file(checkHash(process.exe()))
        if report.reputation < 0:
            print("killing process and sleeping PC")
            # kill the Process
            # os.system("taskkill /im " + process.exe())

            # hibrinate PC
            os.system("shutdown /h")
    except APIError as e:
        if e.code == "NotFoundError":
            try:
                scan_file(process.exe())
            except Exception as e:
                print(e)


def checkProcessLocation(process):
    if process.name() in windows_services_parent_process.keys():
        if process.exe() == windows_services_parent_process[process.name()]:
            print("process location verified")
        else:
            print(process.exe() + " not verified")
            process.kill()
    else:
        print("ignore location of " + process.name())

    # by checking parent process - find abnormal launches i.e. non windows
    # todo:
    # store into dictionary the name of process and pid - only one instance of certain processes should exist wininit, system, services,isass etc
    #
    # check parent process location


def checkHash(path):
    return hashlib.md5(open(path, 'rb').read()).hexdigest()

def check_all_running_exes():

    currentRunningProcesses = set()
    if len(processCurrentlyRunning) == 0:
        currentRunningProcesses = p.getCurrentRunningProcessID()
    else:
        currentRunningProcesses = p.getCurrentRunningProcessID().difference(currentRunningProcesses)
    try:
        print("checking running processes")

        for proc in currentRunningProcesses:
            try:
                process = psutil.Process(proc)
                results = PEExtracter.check_EXE_PE_Header(process.exe())
                print(results)
                if results == 1:
                    print("malware detected - shutting down process")
                    os.system("shutdown /h")
            except Exception as e:
                print(e)
    except Exception as e:
        print(e)


if __name__ == "__main__":
    # CheckRunningProcess()
    check_all_running_exes()
    print("rerun")
   # schedule.every(0.1).seconds.do(CheckRunningProcess)
   # schedule.every(1).seconds.do(check_all_running_exes)
   #  while True:
   #      schedule.run_pending()
   #      time.sleep(1)
