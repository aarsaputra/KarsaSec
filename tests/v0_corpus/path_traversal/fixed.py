import os

def read_user_file(filename):
    base_dir = "/var/www/uploads/"
    safe_filename = os.path.basename(filename)
    filepath = os.path.join(base_dir, safe_filename)
    with open(filepath, "r") as fp:
        return fp.read()
