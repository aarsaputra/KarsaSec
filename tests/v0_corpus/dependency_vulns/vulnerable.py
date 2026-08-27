# Vulnerable dependency import pattern
import vulnerable_lib_v1 as dep

def execute_dep(data):
    return dep.unsafe_process(data)
