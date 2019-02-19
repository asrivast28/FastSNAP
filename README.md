# Fast-SNAP
[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%20v2.0-blue.svg)](LICENSE)

Fast-SNAP stands for Fast SNort using the [Automata Processor](http://micronautomata.com/documentation) (AP).
This repository contains code for parsing the [Snort](https://www.snort.org) rules and converting them into binary images which can be loaded on the AP for Deep Packet Inspection.

## Requirements
The implementation uses the Python API provided by the [APSDK](http://micronautomata.com/apsdk_documentation/latest/group__ap__sdk__py.html). The code was tested using APSDK 1.7.34 and Python 2.7.12.

## Execution
The Snort rules can be downloaded from the website. They can then be converted for execution on the AP by executing the following:
```
python fastsnap.py <path to directory containing .rules files> -c
```
The above is the most conservative mode of operation. Flags can be used to enable support for multiple independent patterns in a rule, negated patterns, patterns with backreferences, etc. The following can be executed for the full usage information:
```
python fastsnap.py --help
```

## Publications
* Roy, Indranil, Ankit Srivastava, Matt Grimm, Marziyeh Nourian, Michela Becchi, and Srinivas Aluru. "Evaluating High Performance Pattern Matching on the Automata Processor." _IEEE Transactions on Computers_ (2019).
* Roy, Indranil, Ankit Srivastava, Marziyeh Nourian, Michela Becchi, and Srinivas Aluru. "High Performance Pattern Matching using the Automata Processor." In _Parallel and Distributed Processing Symposium, 2016 IEEE International_, pp. 1123-1132. IEEE, 2016.
