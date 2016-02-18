#!/usr/bin/env python
"""Receives a list of SHA1 hashes, compares to hash of
running base image files, and kills any matched processes"""
#imports
import hashlib
import argparse
import psutil


#CONSTANTS
BLOCKLIMIT = 65536


#Iterate over running processes and create base file list, include pids
def get_files():
    """Returns a list of process ids and base files"""
    files = []
    for proc in psutil.process_iter():
        try:
            base = proc.exe()
            pid = proc.pid
            files.append([base, pid])
        except psutil.AccessDenied:
            print 'Warning: Access denied getting file path for pid %s' %(str(proc.pid))
    return files


def hash_file(base_file):
    """gets sha1 hash of base file, protects memory"""
    hasher = hashlib.sha1()
    try:
        with open(base_file, 'rb') as tohash:
            content = tohash.read(BLOCKLIMIT)
            while len(content) > 0:
                hasher.update(content)
                content = tohash.read(BLOCKLIMIT)
    except IOError:
        print "Error reading file %s, probably access denied" % (base_file)
    else:
        filehash = hasher.hexdigest()
        return filehash

def killproc(pid):
    """kills provided pid"""
    badproc = psutil.Process(pid)
    try:
        badproc.kill()
    except psutil.NoSuchProcess:
        print "Process no longer exists"


def shacompare(inhashes):
    """Compares hashes from string with provided"""
    files = get_files()
    for base_file in files:
        base_hash = hash_file(base_file[0])
        for test_hash in inhashes:
            if test_hash == base_hash:
                print "Hash match found for file %s with PID %s" %(base_file[0], base_file[1])
                bad_pid = base_file[1]
                print "Killing matched process"
                killproc(bad_pid)

def main():
    """Get SHA1 hashes from command line, set as var, call comparison"""
    parser = argparse.ArgumentParser()
    parser.add_argument("hashes", help="SHA1 hashes to compare with running processes", nargs="*")
    args = parser.parse_args()
    inhashes = args.hashes
    if inhashes:
        shacompare(inhashes)
    else:
        print "Did not receive any input hashes. Run with -h for help. Exiting..."

if __name__ == '__main__':
    main()
