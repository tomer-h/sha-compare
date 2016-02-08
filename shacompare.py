#!/usr/bin/python

#imports
import hashlib
import psutil
import argparse
import os

#Get SHA1 hashes from command line, set as var
parser = argparse.ArgumentParser()
parser.add_argument("hashes", help="SHA1 hashes to compare with running processes", nargs="*")
args = parser.parse_args()
inhashes = args.hashes

#Iterate over running processes and create base file list, include pids
def get_files():
    files = []
    for proc in psutil.process_iter():
        try:
            base = proc.exe()
            pid = proc.pid
        except psutil.AccessDenied:
            print 'Warning: Access denied getting file path for pid %s' %(str(proc.pid))
        else:
            files.append([base, pid])
    return files

#function to create hash
def hash_file(base_file):
    hasher = hashlib.sha1()
    blocklimit = 65536
    try:
        with open(base_file, 'rb') as tohash:
            content = tohash.read(blocklimit)
            while len(content) > 0:
                hasher.update(content)
                content = tohash.read(blocklimit)
    except IOError:
        print "Error reading file %s, probably access denied" % (base_file)
    else:
        filehash = hasher.hexdigest()
        return filehash

def killproc(pid):
    badproc = psutil.Process(pid)
    try:
        badproc.kill()
    except psutil.NoSuchProcess:
        print "Process no longer exists"


def shacompare():
    files = get_files()
    for base_file in files:
        base_hash = hash_file(base_file[0])
        for test_hash in inhashes:
            if test_hash == base_hash:
                print "Hash match found for file %s with PID %s" %(base_file[0], base_file[1])
                bad_pid = base_file[1]
                print "Killing matched process"
                killproc(bad_pid)
            else:
                pass

shacompare()
