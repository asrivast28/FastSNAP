#!/usr/bin/env python

##
# @file fastsnap.py
# @brief Driver script for converting Snort rules.
# @author Ankit Srivastava <asrivast@gatech.edu>
# @version 1.0
# @date 2018-03-09

from argparse import ArgumentParser, ArgumentTypeError
import os
import time
import sys

from rulesconverter import RulesConverter


if __name__ == '__main__':
    def RulesPath(path):
        allFiles = []
        if os.path.isdir(path):
            for subdirs, dirs, files in os.walk(path):
                allFiles.extend(os.path.join(path, name) for name in files if name.endswith('.rules'))
        elif os.path.isfile(path):
            allFiles.append(path)
        else:
            raise ArgumentTypeError, 'The provided path is neither a file nor a directory!'
        return allFiles

    parser = ArgumentParser(description = 'Generate ANML-NFA/AP-FSM from Snort rules.')
    parser.add_argument('rules', help = 'the directory/file from which the Snort rules are to be read',
                        type = RulesPath)
    parser.add_argument('-o', '--out', help = 'directory to which all the files should be written',
                        default = os.getcwd(), metavar = 'DIR')
    parser.add_argument('-m', '--maxstes', help = 'maximum number of STEs per rule in a bucket',
                        type = int, default = 0, metavar = 'S')
    parser.add_argument('-r', '--maxrepeats', help = 'maximum number of bounded repetitions',
                        type = int, default = 0, metavar = 'R')
    parser.add_argument('-i', '--independent', help = 'handle independent patterns in a rule',
                        action = 'store_true')
    parser.add_argument('-n', '--negations', help = 'handle negated patterns',
                        action = 'store_true')
    parser.add_argument('-b', '--backreferences', help = 'handle back references in patterns',
                        action = 'store_true')
    parser.add_argument('-c', '--compile', help = 'compile the generated ANML-NFAs to get AP-FSMs',
                        action = 'store_true')
    parser.add_argument('-l', '--logging', help = 'enable error logging',
                        action = 'store_true')
    args = parser.parse_args()

    if not os.path.exists(args.out):
        os.makedirs(args.out)

    if args.logging:
        sys.stderr = open(os.path.join(args.out, 'error.log'), 'wb')

    t1 = time.time()
    converter = RulesConverter(args.out, args.maxstes, args.maxrepeats, args.independent, args.negations, args.backreferences, args.compile)
    # convert the rules
    converter.convert(args.rules)
    t1 = time.time() - t1
    print '\nTotal time taken in converting the rules:', t1

    # export them as ANML
    t2 = time.time()
    converter.export()
    t2 = time.time() - t2
    print 'Total time taken in exporting:', t2

    if args.logging:
        sys.stderr = sys.__stderr__
