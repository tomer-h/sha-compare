
import hashlib

hasher = hashlib.sha1()
blocklimit = 65536
base_file = '/Users/tomer.hoter/.rvm/rubies/ruby-2.2.2/bin/ruby'
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
    print filehash
