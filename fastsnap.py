#!/usr/bin/env python

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
    parser.add_argument('-l', '--logging', help = 'enable logging',
                        action = 'store_true')
    args = parser.parse_args()

    with open('error.log', 'wb') as e:
        if args.logging:
            sys.stderr = e

        t1 = time.time()
        converter = RulesConverter(args.independent, args.negations, args.backreferences, args.maxstes, args.maxrepeats, args.compile)
        # convert the rules
        converter.convert(args.rules)
        t1 = time.time() - t1
        print '\nTotal time taken in converting the rules:', t1

        # export them as ANML
        t2 = time.time()
        converter.export('test_anml', args.compile)
        t2 = time.time() - t2
        print 'Total time taken in exporting:', t2

        if args.logging:
            sys.stderr = sys.__stderr__
