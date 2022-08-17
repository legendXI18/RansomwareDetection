import schedule
import time
import os
import psutil
import hashlib

from FetchProcessID import FetchProcessID

p = FetchProcessID()
runningEXEDict = {}

def CheckRunningProcess():
    print(("calling setlist 1"))
    p.getCurrentRunningProcessID()
    time.sleep(5)
    print(("calling setlist 2"))
    p.processIDlist2 = p.getCurrentRunningProcessID()

    combinedList = p.processIDlist2.difference(p.processIDlist1)
    print(combinedList)

    p.processIDlist1 = p.processIDlist2
# by checking parent process - lets me find abnormal launches i.e. non windows
    #todo:
    # store into dictionary the name of process and pid - only one instance of certain processes should exist wininit, system, services,isass etc
    #
    # check parent process location

    for proc in combinedList:
        try:

            print("current process")
            process = psutil.Process(proc)
            print(process.name())

            if process.name() in

            print("parent")
            parentProcess = psutil.Process(process.ppid())
            print(parentProcess)
            print(parentProcess.exe())

            print("grandparent")
            grandparentProcess = psutil.Process(parentProcess.ppid())
            print(grandparentProcess)
            print(grandparentProcess.exe())

            print(checkHash(process.exe()))

        except Exception as e:
            print(e)

    print("combined")
    print(combinedList)

def checkHash(path):

    return hashlib.md5(open(path, 'rb').read()).hexdigest()

if __name__ == "__main__":
   # CheckRunningProcess()
    schedule.every(10).seconds.do(CheckRunningProcess)

    while True:
        schedule.run_pending()
        time.sleep(1)