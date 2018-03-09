##
# @file rulesconverter.py
# @author Ankit Srivastava <asrivast@gatech.edu>
# @version 1.0
# @date 2018-03-09

from collections import defaultdict
import os
import re
import sys

from rulesanml import RulesAnml, AnmlException


class RulesConverter(object):
    """
    Class for converting Snort rules to ANML-NFA.
    """
    # list of Snort keywords that are not supported
    _unsupportedKeywords = (
        'byte_test',
        'byte_jump',
        'byte_extract',
    )

    # map of modifier keywords to the corresponding bucket and PCRE keywords
    _keywordsMap = {
        'http_client_body' : ('', 'P'),
        'http_cookie'      : ('', 'C'),
        'http_raw_cookie'  : ('http_cookie', 'K'),
        'http_header'      : ('', 'H'),
        'http_raw_header'  : ('http_header', 'D'),
        'http_method'      : ('', 'M'),
        'http_uri'         : ('', 'U'),
        'http_raw_uri'     : ('http_uri', 'I'),
        'http_stat_code'   : ('', 'S'),
        'http_stat_msg'    : ('', 'Y'),
        'pkt_data'         : ('', ''),
        'file_data'        : ('', ''),
    }

    # compiled patterns for matching and extracting patterns from rules
    _optionPattern = re.compile(r'\((?P<options>.* (?:content|pcre):.*)\)')
    _unsupportedPattern = re.compile(r'(?P<unsupported>%s)'%('|'.join(_unsupportedKeywords)))
    _sidPattern = re.compile(r'sid:(?P<sid>\d+);')
    _genericPattern = re.compile(r'(?P<content>(?P<type>content|pcre):.*?)(?=content:|pcre:|$)')
    _genericPcrePattern = re.compile(r'(?P<pcre>pcre:"/.*/\w*)(?P<modifier>%s)(?P<suffix>\w*")'%('|'.join(sm[-1] for sm in _keywordsMap.itervalues() if sm[-1] != '')))
    _keywordsPattern = re.compile(r'(?P<keyword>%s);'%('|'.join(_keywordsMap.iterkeys())))
    _contentPattern = re.compile(r'content:(?P<negation>!?)"(?P<string>.*)";')
    _paramPattern = re.compile(r'(?P<name>offset|depth|distance|within):(?P<value>\d+)')
    _pcrePattern = re.compile(r'pcre:(?P<negation>!?)"/(?P<pattern>.*?)[/]?(?P<modifiers>\w*)";')
    _escapePattern = re.compile(r'(\.|\^|\$|\*|\+|\?|\(|\)|\{|\[|\\|\/)')
    _lookaheadPattern = re.compile('(\(\?=.*\))')
    _pipePattern = re.compile(r'(\|(?P<suffix>(?:[A-F\d]{2} ?)*)\|)')

    # cached modifier keyword map
    _modifierKeywordsMap = None

    # print error messages
    _printMessages = True

    @classmethod
    def enableErrorMessages(cls):
        cls._printMessages = True

    @classmethod
    def disableErrorMessages(cls):
        cls._printMessages = False

    @classmethod
    def _error_message(cls, message):
        if cls._printMessages:
            sys.stderr.write(message)
            sys.stderr.flush()

    @classmethod
    def _print_statistics(cls, totalRules, patternRules, supportedRules, convertedRules):
        if cls._printMessages:
            print 'Total number of rules:', totalRules
            print 'Number of rules with pattern matching keywords:', patternRules
            print 'Number of supported rules:', supportedRules
            print 'Number of converted rules:', convertedRules

    @classmethod
    def _get_modifier_keyword(cls, modifier):
        """
        Creates map from PCRE modifier to the corresponding keyword,
        if not already created, and returns the map.
        """
        if cls._modifierKeywordsMap is None:
            cls._modifierKeywordsMap = {}
            for keyword, value in cls._keywordsMap.iteritems():
                if value[-1]:
                    cls._modifierKeywordsMap[value[-1]] = keyword
        return cls._modifierKeywordsMap[modifier]

    @classmethod
    def _get_pattern_matching_rules(cls, rulesFile):
        """
        Extracts all the rules with pattern matching keywords.
        """
        ruleCount = 0
        fileRules = []
        for rule in rulesFile:
            rule = rule.strip()
            if not rule or rule[0] == '#':
                # skip commented rules, denoted by '#'
                # also skip empty lines
                continue
            ruleCount += 1
            matched = cls._optionPattern.search(rule)
            if matched is None:
                cls._error_message("Skipping the following rule as it doesn't have any pattern matching keywords.\n%s\n\n"%(rule))
            else:
                fileRules.append(rule)
        return fileRules, ruleCount

    @classmethod
    def _get_supported_rules(cls, allRules):
        """
        Filters all the rules with unsupported keywords.
        """
        supportedRules = []
        for rule in allRules:
            matched = cls._unsupportedPattern.search(rule)
            if matched is not None:
                cls._error_message('Skipping the following rule as the keyword "%s" is not supported.\n%s\n\n'%(matched.group('unsupported'), rule))
            else:
                supportedRules.append(rule)
        return supportedRules

    @classmethod
    def _get_all_rules(cls, rulesFiles):
        """
        Gets all the supported rules from the rules file(s).
        """
        totalRuleCount = 0
        patternRuleCount = 0
        supportedRules = []
        for f in rulesFiles:
            with open(f, 'rb') as rulesFile:
                fileRules, fileRuleCount = cls._get_pattern_matching_rules(rulesFile)
                totalRuleCount += fileRuleCount
                patternRuleCount += len(fileRules)
                fileSupportedRules = cls._get_supported_rules(fileRules)
                supportedRules.extend(fileSupportedRules)
        return supportedRules, totalRuleCount, patternRuleCount

    def __init__(self, directory, maxStes, maxRepeats, independent, negations, backreferences, compile):
        """
        Constructor. Stores some of the program options.
        """
        self._directory = directory
        self._independent = independent
        self._negations = negations
        self._compile = compile

        self._sids = set()
        self._unsupported = set()

        self._anml = RulesAnml(maxStes, maxRepeats, backreferences)

        self._patternCount = defaultdict(int)

    def _combine_independent_patterns(self, independentPatterns):
        """
        Combines independent patterns provided as a list.
        """
        patternString = ''
        numPatterns = len(independentPatterns)
        if numPatterns > 1:
            for p in xrange(0, numPatterns - 1):
                if independentPatterns[p][0] == '^':
                    if independentPatterns[-1][0] != '^':
                        temp = independentPatterns[-1]
                        independentPatterns[-1] = independentPatterns[p]
                        independentPatterns[p] = temp
                else:
                    independentPatterns[p] = '.*' + independentPatterns[p]
                patternString += '(?=%s)'%(independentPatterns[p])
            if independentPatterns[-1][0] != '^':
                patternString += '.*'
        patternString += independentPatterns[-1]
        return patternString

    def _get_independent_patterns(self, patterns):
        """
        Extracts indepdent patterns from given content/pcre for a rule.
        """
        independentPatterns = []
        numLookaheads = 0
        for p in patterns:
            relative = False
            thisModifiers = ''
            thisPattern = ''
            negation = ''
            isContent = False

            if p.startswith('content'):
                isContent = True
                content = self._contentPattern.search(p)
                if content is not None:
                    offset = 0
                    depth = -1
                    negation = content.group('negation')
                    contentString, escapePatternCount = self._escapePattern.subn(lambda m: '\\' + m.group(1), content.group('string'))
                    class PipeSubFunc(object):
                        _hexPattern = re.compile(r'([\dA-F]{2}) ?')
                        def __init__(self):
                            self.hexPatternCount = 0
                        def __call__(self, m):
                            subString, subCount = self._hexPattern.subn(lambda m : r'\x' + m.group(1), m.group('suffix'))
                            self.hexPatternCount += subCount
                            return subString

                    pipeSubFunc = PipeSubFunc()
                    contentString, subCount = self._pipePattern.subn(pipeSubFunc, contentString)
                    if p.find('nocase;') != -1:
                        thisModifiers = 'i'
                    for param in self._paramPattern.finditer(p):
                        name = param.group('name')
                        value = int(param.group('value'))
                        if value < 0:
                            raise RuntimeError, 'Handling of negative parameter values is not implemented'
                        offset = value if name in ['offset', 'distance'] else offset
                        depth = value if name in ['depth', 'within'] else depth
                        relative = True if name in ['distance', 'within'] else relative
                    ps = []
                    if offset != 0 or depth != -1:
                        contentSize = len(contentString) - escapePatternCount - (pipeSubFunc.hexPatternCount * 3)
                        if depth != -1 and depth < contentSize:
                            raise RuntimeError, 'Encountered depth/within less than content string length'
                        if not relative:
                            ps.append('^')
                        end = (offset + depth) - contentSize if depth != -1 else 0
                        if offset > 0 or end > offset:
                            ps.append('.{%d'%offset)
                            if end > offset:
                                ps.append(',%d'%end)
                            ps.append('}')
                        if depth == -1:
                            ps.append('.*')
                    elif relative:
                        ps.append('.*')
                    ps.append(contentString)
                    thisPattern = ''.join(ps)
                else:
                    raise RuntimeError, "Provided content pattern didn't match the standard pattern"
            else:
                matched = self._pcrePattern.search(p)
                if matched is not None:
                    negation = matched.group('negation')
                    thisModifiers = matched.group('modifiers')
                    if thisModifiers.find('R') != -1:
                        thisModifiers = thisModifiers.replace('R', '')
                        relative = True
                    if thisModifiers.find('B') != -1:
                        print p
                    # 'O' is fast pattern matching modifier; we don't need it
                    thisModifiers = thisModifiers.replace('O', '')
                    # 'G' is same as 'U' in PCRE, for some reason
                    thisModifiers = thisModifiers.replace('G', 'U')
                    thisPattern = matched.group('pattern')
                    numLookaheads += self._lookaheadPattern.subn('', thisPattern)[1]
                else:
                    raise RuntimeError, "Provided pcre pattern didn't match the standard pattern"
            negation = bool(negation)
            if negation and not self._negations:
                raise RuntimeError, "Can't handle negations"
            if relative and len(independentPatterns) > 0:
                prevPattern, prevModifiers = independentPatterns[-1][0]
                if negation is not independentPatterns[-1][1]:
                    if not negation:
                        raise RuntimeError, 'Unable to handle dependence on negative expressions'
                    if isContent:
                        if depth != -1:
                            if independentPatterns[-1][2] is None:
                                independentPatterns[-1][2] = ('/%s/%s'%(thisPattern, thisModifiers), offset + depth)
                            else:
                                raise RuntimeError, 'Unable to handle more than one dependent negations'
                        else:
                            raise RuntimeError, 'Unable to handle dependent unbounded negations'
                    else:
                        raise RuntimeError, 'Unable to handle dependent negations of PCRE type'
                elif independentPatterns[-1][2] is not None:
                    raise RuntimeError, 'Unable to add dependent expression to an expression with negated dependent'
                elif thisModifiers != prevModifiers:
                    prevPattern = '(?%s:%s)'%(prevModifiers, prevPattern)
                    thisPattern = '(?%s:%s)'%(thisModifiers, thisPattern)
                    independentPatterns[-1][0] = (prevPattern + thisPattern, '')
                else:
                    independentPatterns[-1][0] = ('%s(?:%s)'%(independentPatterns[-1][0][0], thisPattern), thisModifiers)
            else:
                independentPatterns.append([[thisPattern, thisModifiers], negation, None])
        return [('/%s/%s'%tuple(pattern), negation, dependent) for pattern, negation, dependent in independentPatterns]

    def convert(self, rulesFiles):
        """
        Convert all the rules in given rules files to the corresponding ANML-NFA or PCRE.
        """
        outputFiles = {}
        sids = set()
        unsupported = set()

        allRules, totalRuleCount, patternRuleCount = self._get_all_rules(rulesFiles)
        patternCount = defaultdict(int)

        for rule in allRules:
            matched = self._sidPattern.search(rule)
            if matched is None:
                raise RuntimeError, 'Encountered a rule with no SID'
            sid = int(matched.group('sid'))
            sids.add(sid)
            contentVectors = defaultdict(list)
            for pattern in self._genericPattern.finditer(rule):
                keyword = 'general'
                raw = False
                thisContent = pattern.group('content')
                if pattern.group('type') == 'content':
                    matched = self._keywordsPattern.search(thisContent)
                    if matched is not None:
                        keyword = matched.group('keyword')
                else:
                    matched = self._genericPcrePattern.search(thisContent)
                    if matched is not None:
                        pcreString = matched.group('pcre') + matched.group('suffix')
                        contentString = self._genericPcrePattern.sub('', thisContent, count = 1)
                        thisContent = pcreString + contentString
                        keyword = self._get_modifier_keyword(matched.group('modifier'))
                raw = rule.find('rawbytes;') != -1
                if keyword in self._keywordsMap and self._keywordsMap[keyword][0]:
                    raw = raw or bool(self._keywordsMap[keyword][0])
                    keyword = self._keywordsMap[keyword][0]
                contentVectors[(keyword, raw)].append(thisContent)
            convertedStrings = {}
            handled = True
            for bucket, patterns in contentVectors.iteritems():
                try:
                    if sid in [26242, 20207, 26852, 26853, 27133, 27829, 27830]:
                        raise RuntimeError, "Skipping rule because it takes LOT of time in compilation"
                    independentPatterns = self._get_independent_patterns(patterns)
                    if not self._independent and len(independentPatterns) > 1:
                        raise RuntimeError, "Can't handle multiple independent patterns per rule"
                    convertedStrings[bucket] = independentPatterns
                except RuntimeError, e:
                    unsupported.add(sid)
                    self._error_message('\nGetting pattern for rule with SID %d failed.\n%s\n'%(sid, str(e)))
                    handled = False
                    break
            if not handled:
                continue
            for bucket, patterns in convertedStrings.iteritems():
                keyword = bucket[0] + '_raw' if bucket[1] else bucket[0]
                try:
                    self._anml.add(keyword, sid, patterns)
                except AnmlException, e:
                    unsupported.add(sid)
                    self._error_message(str(e))
                else:
                    self._patternCount[keyword] += len(patterns)
                #writeString = '%d: %s'%(sid, patterns[0])
                #if self._writeFiles and keyword not in outputFiles:
                    #outputFiles[keyword] = open(keyword + '.txt', 'wb')
                #if self._writeFiles:
                    #outputFiles[keyword].write(writeString + '\n')
                #else:
                    #print writeString
        self._print_statistics(totalRuleCount, patternRuleCount, len(allRules), len(sids - unsupported))
        #print self._patternCount

    def export(self):
        """
        Write out the ANML-NFA or the AP-FSM to the given directory.
        """
        self._anml.export(self._directory)
        if self._compile:
            self._anml.compile(self._directory)
