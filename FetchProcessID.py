import schedule
import time
import os
import psutil

class FetchProcessID:
    processIDlist1 = set()
    processIDlist2 = set()

    def __init__(self):
        print("started Process ID fetcher")
        self.processIDlist1 = self.getCurrentRunningProcessID()


    def getCurrentRunningProcessID(self):
        #  pipe from command.
        output = os.popen('wmic process get description, processid').read()
        # get all running processID
        output = output.split()
        list_all_processID = {int(x) for x in output if x.isdigit()}
        print(list_all_processID)

        return list_all_processID




