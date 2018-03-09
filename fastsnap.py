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

    parser = ArgumentParser()
    parser.add_argument('rules', help = 'Specify the directory/file from which rules are to be extracted.',
                        type = RulesPath)
    parser.add_argument('-i', '--independent', help = 'Flag for specifying that independent patterns should be handled.',
                        action = 'store_true')
    parser.add_argument('-n', '--negations', help = 'Flag for specifying that negations should be handled.',
                        action = 'store_true')
    parser.add_argument('-b', '--backreferences', help = 'Flag for specifying that back references should be handled.',
                        action = 'store_true')
    parser.add_argument('-m', '--maxstes', help = 'Maximum number of STEs allowed for one rule to be added in a bucket.',
                        type = int, default = 0, metavar = 'N')
    parser.add_argument('-c', '--compile', help = 'Flag for specifying that the generated anml should be compiled.',
                        action = 'store_true')
    parser.add_argument('-l', '--logging', help = 'Flag for specifying that logging should be enabled.',
                        action = 'store_true')
    args = parser.parse_args()

    with open('error.log', 'wb') as e:
        if args.logging:
            sys.stderr = e

        t1 = time.time()
        converter = RulesConverter(args.independent, args.negations, args.backreferences, args.maxstes, args.compile)
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
