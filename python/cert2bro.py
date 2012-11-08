#!/usr/bin/env python
# This is a simple utility to convert PEM format scripts into a cert stanza
# used by Bro IDS
#
# Written by Lou Ruppert
#
# openssl x509 -in cert.pem -inform PEM -noout -subject
# openssl x509 -in cacert.crt -inform PEM -outform DER | \
#   hexdump -v -e '1/1 "\\\x"' -e '1/1 "%02X"' > my-cert-hexesc.der
#
import getopt
import sys
import os
import re


#
# Correct mistakes politely.
#
def usage():
    print "Usage: %s -i inputfile [-o outputfile]" % sys.argv[0]
    sys.exit()


# Reusable goodness
def main():
    # Set the table
    infile = None
    outfile = None

    if len(sys.argv) <= 1:
        usage()

    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "i:o:h", ["help"])

    except getopt.GetoptError, err:
        print "Error: " + str(err)
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-i"):
            infile = a
        elif o in ("-o"):
            outfile = a
    if (infile):
        bro_stanza = convert_cert(infile)
    else:
        usage()

    if (outfile):
        save_cert(bro_stanza, outfile)
    else:
        print bro_stanza


# Read a PEM cert file and return a string containing a bro cert stanza
def convert_cert(infile, openssl="/usr/bin/openssl",
                 hexdump="/usr/bin/hexdump"):
    subject = None
    hexcrt = None
    bro_stanza = None

    if not os.path.isfile(infile):
        raise IOError("No certificate file at %s" % infile)

    if not os.path.exists(openssl):
        raise IOError("OpenSSL binary not found at %s" % openssl)

    if not os.path.exists(hexdump):
        raise IOError("hexdump binary not found at %s" % hexdump)

    rsub = os.popen("%s x509 -in %s -inform PEM -noout -subject" % (openssl,
                     infile))
    for rsubline in rsub:
        m = re.search('subject= \/(.*)\n', rsubline)
        if (m != None):
            subject = str(m.group(1))

    if (subject is None):
        raise Exception("Unable to parse a certificate subject out of %s" %
                         infile)

    rhex = os.popen("%s x509 -in %s -inform PEM -outform DER| %s -v -e '1/1 \"\\x\"' -e '1/1 \"%%02X\"'" %
                    (openssl, infile, hexdump))
    for rhexline in rhex:
        m = re.search('([x,0-9,A-F]+)', rhexline)
        if (m != None):
            hexcrt = "\\x".join(m.group(1).split("x"))

    ## I don't know if it's possible to not have a value here, but I'd rather
    ## be sure.
    if (hexcrt):
        bro_stanza = "redef SSL::root_certs += {\n\t[\"%s\"] = \"%s\"\n};" % (subject, hexcrt)
    else:
        raise Exception("Unable to parse a certificate body out of %s" % infile)
    return bro_stanza


# Save the cert in a file, if that's your thing.
def save_cert(bro_stanza, outfile):
    if (outfile is not None and not os.path.exists(outfile)):
        print "Using output file: %s" % outfile
        outf = open(outfile, "w")
        outf.write(bro_stanza)
        outf.close()


if __name__ == "__main__":
    main()
