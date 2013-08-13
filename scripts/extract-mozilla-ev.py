#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#=======================================================================
#
# extract_mozilla_ev_data.py
# --------------------------
# Simple Python test program that extracts EV data from
# the Mozilla source code. The program is a replacement for the
# extract program that requires Windows CPP or other C compiler.
# https://github.com/nabla-c0d3/extract_mozilla_ev_oids/blob/master/extract_mozilla_ev_oids.py
#
# Note: This code assumes Python 2.6.x.
#
#
# (c) 2013 Secworks Sweden AB
# Joachim Strombergson
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
# Constants.
#-------------------------------------------------------------------
MOZ_SOURCE_URL = "https://mxr.mozilla.org/mozilla-central/source/security/manager/ssl/src/nsIdentityChecking.cpp?raw=1"


#-------------------------------------------------------------------
# output_ev_data()
#
# Output EV data in terms of OIDs and fingerprints in the
# given formats. If output_name is given, the data will be written
# to a file with the given name. If no name is given,
# std out will be used.
#-------------------------------------------------------------------
def output_ev_data(ev_data_db, output_format, output_name, verbose):
    del ev_data_db['status']

    oid_list = []
    for nr in ev_data_db.keys():
        oid_list.append(ev_data_db[nr]['oid'])

    if output_format == 'sslyze':
        print oid_list
                            
    elif output_format == 'json':
        if output_name:
            with open(output_name, 'wb') as json_file:
                json.dump(ev_data_db, json_file)
        else:
            print json.dumps(ev_data_db)

    else:
        for oid in oid_list:
            print oid


#-------------------------------------------------------------------
# extract_ev_data()
#
# Parses the Mozilla source code and extracts the OIDs and
# SHA fingerprints.
#-------------------------------------------------------------------
def extract_ev_data(url, verbose):
    if verbose:
        print "Extracting EV data from url:"
        print url

    try:
        html = urllib2.urlopen(url).read()
    except URLError as e:
        print e.reason 
    html_lines = html.splitlines()
 
    # Initial parser. Scans through all lines and creates a db with one
    # array of lines for each certifcate struct found in the source.
    struct_name = "static struct nsMyTrustedEVInfo myTrustedEVInfos"
    in_struct = False
    in_cert = False
    key = 0
    tmp_db = {}
    for line in html_lines:
        if in_cert == 1 and "}" in line:
            in_cert = False
            tmp_db[key] = tmp_list
            if verbose:
                print "Extracted cert lines for cert %d:" % key
                print tmp_list
            key += 1

        if in_cert == 1:
            tmp_list.append(line.strip())
        
        if in_struct == 1 and "{" in line:
            in_cert = True
            tmp_list = []
            
        if struct_name in line:
            in_struct = True
        elif in_struct == 1 and "};" in line:
            in_struct = False

    if verbose:
        print "\nExtracted certs:"
        print tmp_db
        print

    # Secondary parser. Scans through the db with extracted certs
    # and builds a new db with cleaned up data containing OIDs, fingerprints
    # and some sort of info/identifier based on CN, OU etc.
    # If we find a test certificate or OID the extracted entries for that
    # certificate is discarded.
    extracted_db = {}
    key = 0
    for tmp_list in tmp_db.itervalues():
        test_cert = False
        tmp_info = tmp_list[0]
        tmp_oid = (tmp_list[1])[1:-2]
        tmp_fingerprint = (((tmp_list[4])[1:-2]).replace(':', '')).lower()

        if ("testing EV signature" in tmp_info) or\
               ("Sample Certification Authority" in tmp_info):
            pass
        else:
            extracted_db[key] = {}
            extracted_db[key]['info'] = tmp_info
            extracted_db[key]['oid'] = tmp_oid
            extracted_db[key]['fingerprint'] = tmp_fingerprint
            key += 1

    if verbose:
        print "\nExtracted database:"
        print extracted_db

    extracted_db['status'] = True
    return extracted_db


#-------------------------------------------------------------------
# main()
#
# Parse command line arguments and extract EV data based on the
# given commands and options.
#-------------------------------------------------------------------
def main():

    parser = argparse.ArgumentParser(description='Extract the EV data fields OID and fingerprint from Mozilla source code and other URLs. The extracted EV data can be emitted in a few different formats such as generic with one OID per line, a format suitable for inclusion on sslyzer or a JSON blob.')

    parser.add_argument("-f", "--format", action="store", default="generic",
                        help="Emit data in specific format. Acceptable values are 'generic', 'sslyze' and 'json'. Default is 'generic'.")
    
    parser.add_argument("-u", "--url", action="store", default=MOZ_SOURCE_URL,
                        help="Extract EV data from the given URL. If no URL is given, the URL for Mozilla will be used.")

    parser.add_argument("-o", "--output_file", action="store",
                        help="Save extracted EV data to the given output file. If no file is given, std out will be used.")

    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    ev_data_db = extract_ev_data(args.url,  args.verbose)
    if ev_data_db['status']:
        output_ev_data(ev_data_db, args.format, args.output_file, args.verbose)
    else:
        print "Error: No EV data could be extracted from the url."

    
#-------------------------------------------------------------------
# __name__
#
# Python name mangling thingy to run if called stand alone.
#-------------------------------------------------------------------
if __name__ == '__main__':
    main()

#=======================================================================
# EOF extract_mozilla_ev_data.py
#=======================================================================
