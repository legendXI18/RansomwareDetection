import time
import os

from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler


paths = []

#start
while True:
    try:
        path = str(input("please Enter a Path for monitoring: "))
        print(os.path.exists(path))

        if path == "exit":
            print("exiting Program")
            quit()

        if path == "done":
            break

        if not os.path.exists(path):
            print("Please enter a VALID Path")

        print("Path has been added")
        paths.append(path)
    except ValueError:
        raise ValueError("please enter a valid Path")
        # better try again... Return to the start of the loop
        continue


#paths = ["K:/me", "J:/test"]

# Empty list of observers
observers = []
canaryFileCount = 0
my_observer = Observer()

def on_created(event):
    print(f"{event.src_path} has been created!")

def on_deleted(event):
    print(f"Someone deleted {event.src_path}!")

def on_modified(event):
    print(f" {event.src_path} has been modified - Calculating entropy")
    os.get
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

    for line in paths:
        my_observer.schedule(my_event_handler, line)
        observers.append(my_observer)

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
