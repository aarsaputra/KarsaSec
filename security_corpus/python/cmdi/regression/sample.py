import os


def run_script_regression():
    script_name = input('Enter script: ')
    os.popen("python3 " + script_name)
