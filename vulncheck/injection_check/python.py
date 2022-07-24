


def Check_if_db_used(code):
    files = code.tree
    probable_files = []
    pattern = ""
    for file in files:
        if file.endswith('.py'):
            probable_files.append(file)
        