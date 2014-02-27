#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#=======================================================================
#
# ios_parser.py
# -------------
# Simple Python program that extracts and parses certs for iOS
# published by Apple.
#
#
# Author:  Joachim Strombergson
# (c) 2013 Secworks Sweden AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#=======================================================================

#-------------------------------------------------------------------
# Imports.
#-------------------------------------------------------------------
import urllib2
import argparse
import json


#-------------------------------------------------------------------
# extract_ios_certs()
#
# Extract the certs found at the URL. Note that the parsing
# is hard coded and must be change if/when Apple changes
# their format.
#-------------------------------------------------------------------
def extract_ios_certs(url, verbose):
    if verbose:
        print("Extracting iOS CA data from url:")
        print(url)

    try:
        html = urllib2.urlopen(url).read()
    except URLError as e:
        print(e.reason)
    html_lines = html.splitlines()

    cert_ctr = 0
    in_certs = False
    for line in html_lines:
        if in_certs:
            print(line)

        if "Certificate:" in line:
            in_certs = True
            cert_ctr += 1
        if "</table>" in line:
            in_certs = False

    return cert_ctr
    

#-------------------------------------------------------------------
# main()
#-------------------------------------------------------------------
def main():
    # This is the URL at Apple we will try to parse.
    url = 'http://support.apple.com/kb/ht5012'
    verbose = True

    cert_ctr = extract_ios_certs(url, verbose)
    print("Number of certs: %d" % cert_ctr)
          
    
#-------------------------------------------------------------------
# __name__
#
# Python name mangling thingy to run if called stand alone.
#-------------------------------------------------------------------
if __name__ == '__main__':
    main()

#=======================================================================
# EOF ios_parser.py
#=======================================================================

