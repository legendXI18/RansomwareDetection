import time
import os
#https://thepythoncorner.com/posts/2019-01-13-how-to-create-a-watchdog-in-python-to-look-for-filesystem-changes/
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler


paths = []
canaryNames = {}

#start
while True:
    try:
        path = str(input("Please Enter a Path for monitoring: "))
      #  print(os.path.exists(path))

        if path == "exit":
            print("exiting Program")
            quit()

        if path == "done":
            break

        if not os.path.exists(path):
            print("Please enter a VALID Path")
        else:
            print("Path has been added")
            paths.append(path)
    except ValueError:
        raise ValueError("please enter a valid Path")
        # better try again... Return to the start of the loop
        continue



# Empty list of observers
observers = []
canaryFileCount = 0
my_observer = Observer()

def format_Path(path):

    return "\\".join(path.split("\\")[:-1])

def on_created(event):
    print(f"{event.src_path} has been created!")

def on_deleted(event):
    print(f"removing observer {event.src_path}!")
    print(canaryNames.get(format_Path(event.src_path)))
    my_observer.unschedule(canaryNames.get(format_Path(event.src_path)))

def on_modified(event):
    print(f" {event.src_path} has been modified - Calculating entropy")

def on_moved(event):
    print(f"moved {event.src_path} to {event.dest_path}")


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
