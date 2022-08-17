
import time
import os,random
import psutil
import re

#https://thepythoncorner.com/posts/2019-01-13-how-to-create-a-watchdog-in-python-to-look-for-filesystem-changes/
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler


paths = []
canaryNames = {}
downloadPath = "K:\downloads"

password = "default"

#start
while True:
    try:
        path = str(input("Please Enter a Path for monitoring: "))
      #  print(os.path.exists(path))
        print(random.choice(os.listdir("C:\\")))
        if path == "exit":
            print("exiting Program")
            quit()

        if path == "done":
            print("added downloads")
            paths.append(downloadPath)
            break

        if not os.path.exists(path):
            print("Please enter a VALID Path")
        else:
            print("Path has been added")
            paths.append(path)
    except ValueError:
        raise ValueError("please enter a valid Path")

        continue



# Empty list of observers
observers = []
canaryFileCount = 0
my_observer = Observer()


# def check_process(filename):
#     for proc in psutil.process_iter():
#         try:
#             # this returns the list of opened files by the current process
#             flist = proc.open_files()
#             if flist:
#                 print(proc.pid, proc.name)
#                 for nt in flist:
#                     print("\t", nt.path)
#
#         # This catches a race condition where a process ends
#         # before we can examine its files
#         except psutil.NoSuchProcess as err:
#             print("****", err)
#         except psutil.AccessDenied:
#             continue

def check_extentions(file_Ext):
    if file_Ext != "":
        split = file_Ext.split(".")
        split = list(filter(None, split))
        with open('known_extensions', encoding='utf8') as f: temp = f.read().splitlines()
#todo Move logic outside this method to stop it being called every time ( only need it called once)
        with open('known_extensions', encoding='utf8') as ke:
            lines = ke.readlines()
            known_extensions_split = [x for segments in temp for x in segments.split(".")]
            known_extensions_split_set = set(known_extensions_split)

            for extension in split:
                if extension in known_extensions_split_set:
                    print(extension)

                    print('ransomware detected')
                    print('Hibernating PC')
               # os.system("shutdown /h")
                else:
                    print('not malicous')




def format_Path(path):

    return "\\".join(path.split("\\")[:-1])

def on_created(event):
    print(f"{event.src_path} has been created!")

def on_deleted(event):
    print(f"removing observer {event.src_path}!")
    print(canaryNames.get(format_Path(event.src_path)))
  #  my_observer.unschedule(canaryNames.get(format_Path(event.src_path)))

def on_modified(event):
    print(f" {event.src_path} has been modified - Calculating entropy")

    #check_process(event.src_path)
    # TODO - move duplicated logic into method
    file = os.path.splitext(event.src_path)
    file_extension = file[1]
    print("ext: " + file_extension)
    #output_key("bob")
    check_extentions(file_extension)


def on_moved(event):
    print(f"moved {event.src_path} to {event.dest_path}")

    #TODO - move duplicated logic into method
    file =  os.path.splitext(event.dest_path)
    file_extension = file[1]
    print("ext: " + file_extension)

    check_extentions(file_extension)

def output_key(extractedKey):
    f = open("key.txt", "w+")
    f.write(extractedKey)
    f.close()
    #input
    input = "./key.txt"

    #output
    output = "./output.zip"
    # compress level
    com_lvl = 5
    # compressing file
    #pyminizip.compress(input, None, output,
    #                   password, com_lvl)


if __name__ == "__main__":

    patterns = ["*"]
    ignore_patterns = None
    ignore_directories = False
    case_sensitive = True
    my_event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)
    my_event_handler.on_created = on_created
    my_event_handler.on_deleted = on_deleted
    my_event_handler.on_modified = on_modified
    my_event_handler.on_moved = on_moved

    go_recursively = False
    # paths = ["K:/me", "J:/test"]

    for line in paths:
        my_observer.schedule(my_event_handler, line)
        x = my_observer.schedule(my_event_handler, line)
        print(x)
        canaryNames[line] = x

    print(canaryNames)
    my_observer.start()
    try:
        while True:
            # Poll every second
            time.sleep(1)

    except KeyboardInterrupt:
        for o in observer:
            o.unschedule_all()

            # Stop observer if interrupted
            o.stop()

    for o in observer:
        # Wait until the thread terminates before exit
        o.join()


