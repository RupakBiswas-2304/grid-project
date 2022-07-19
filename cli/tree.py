# function for listing all the files in tmp folder
import os

def list_files(path):
    files = []
    for file in os.listdir(path):
        if os.path.isfile(os.path.join(path, file)):
            files.append(f"{path}/{file}")
        else:
            files.extend(list_files(os.path.join(path, file)))
    return files