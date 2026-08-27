def read_user_file(filename):
    filepath = "/var/www/uploads/" + filename
    with open(filepath, "r") as fp:
        return fp.read()
