from argparse import ArgumentParser, ArgumentTypeError
import os
import time

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
    parser.add_argument('--rules', help = 'Specify the directory/file from which rules are to be extracted.',
                        required = True, type = RulesPath)
    parser.add_argument('--independent', help = 'Flag for specifying if independent patterns should be handled.',
                        action = 'store_true')
    parser.add_argument('--negations', help = 'Flag for specifying if negations should be handled.',
                        action = 'store_true')
    parser.add_argument('--compile', help = 'Flag for specifying if the anml should be compiled.',
                        action = 'store_true')
    args = parser.parse_args()

    t = time.time()
    converter = RulesConverter(args.independent, args.negations, args.compile)
    # first determine which rules are not unsupported
    supported, unsupported = converter.convert(args.rules)
    print len(supported), len(unsupported)
    # now reset the converter
    converter.reset()
    # disable the error messages as they have been already output
    converter.disableErrorMessages()
    # convert again, only supported rules this time
    converter.convert(args.rules, unsupported)
    t = time.time() - t
    print t
    # export them as ANML
    t = time.time()
    converter.export('test_anml', args.compile)
    t = time.time() - t
