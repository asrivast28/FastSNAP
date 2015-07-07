from collections import defaultdict
import os
import re
from sys import stderr

from anmlrules import AnmlRules, AnmlException


class RulesConverter(object):
    """
    Class for converting Snort rules to ANML. 
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
            stderr.write(message)
            stderr.flush()

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
    def _get_file_options(cls, rulesFile):
        """
        Extracts all the supported options from the given rules file.
        The argument should be a file object.
        """
        fileOptions = []
        for rule in rulesFile:
            rule = rule.strip()
            if not rule or rule[0] == '#':
                # skip commented rules, denoted by '#'
                # also skip empty lines
                continue
            matched = cls._optionPattern.search(rule)
            if matched is not None:
                newOption = matched.group('options')
                matched = cls._unsupportedPattern.search(newOption)
                if matched is not None:
                    cls._error_message('Skipping the following rule as the keyword "%s" is not supported.\n%s\n\n'%(matched.group('unsupported'), rule))
                else:
                    fileOptions.append(newOption)
            else:
                cls._error_message("Skipping the following rule as it doesn't have any pattern matching keywords.\n%s\n\n"%(rule))
        return fileOptions

    @classmethod
    def _get_all_options(cls, rulesFiles):
        """
        Gets all the supported options from the rules file(s).
        """
        allOptions = []
        for f in rulesFiles:
            with open(f, 'rb') as rulesFile:
                allOptions.extend(cls._get_file_options(rulesFile))
        return allOptions

    def __init__(self, independent, negations, compile):
        """
        Constructor. Stores some of the program options.
        """
        self._independent = independent
        self._negations = negations
        self._compile = compile

        self._sids = set()
        self._unsupported = set()

        self._anml = AnmlRules()

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

            if p.startswith('content'):
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
                            raise RuntimeError, 'Handling of negative parameter values is not implemented!'
                        offset = value if name in ['offset', 'distance'] else offset
                        depth = value if name in ['depth', 'within'] else depth
                        relative = True if name in ['distance', 'within'] else relative
                    ps = []
                    if offset != 0 or depth != -1:
                        contentSize = len(contentString) - escapePatternCount - (pipeSubFunc.hexPatternCount * 3)
                        if depth != -1 and depth < contentSize:
                            raise RuntimeError, 'Encountered depth/within less than content string length!'
                        if not relative:
                            ps.append('^')
                        end = (offset + depth) - contentSize if depth != -1 else 0
                        if offset > 0 or end > offset:
                            ps.append('.{%d'%(offset))
                            if end > offset:
                                ps.append(',%d'%(end))
                            ps.append('}')
                        if depth == -1:
                            ps.append('.*')
                    elif relative:
                        ps.append('.*')
                    ps.append(contentString)
                    thisPattern = ''.join(ps)
                else:
                    raise RuntimeError, "Provided content pattern didn't match the standard pattern!"
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
                    raise RuntimeError, "Provided pcre pattern didn't match the standard pattern!"
            if thisModifiers:
                thisPattern = '(?%s:%s)'%(thisModifiers, thisPattern)
            if negation:
                if not self._negations:
                    raise RuntimeError, "Can't handle negations!"
            if relative and len(independentPatterns) > 0:
                if negation is not independentPatterns[-1][1]:
                    #print independentPatterns, thisPattern
                    raise RuntimeError, 'Unable to handle negations of this kind!' 
                independentPatterns[-1][0] = independentPatterns[-1][0] + thisPattern
            else:
                independentPatterns.append([thisPattern, negation])
        return [('/%s/'%(pattern), negation) for pattern, negation in independentPatterns]

    def reset(self):
        """
        Reset ANML rules.
        """
        self._anml.reset()

    def convert(self, rulesFiles, unsupported = set()):
        """
        Convert all the rules in given rules files to the corresponding ANML or PCRE. 
        """
        outputFiles = {}
        sids = set()

        for option in self._get_all_options(rulesFiles):
            matched = self._sidPattern.search(option)
            if matched is None:
                raise RuntimeError, "Encountered a rule with no SID!"
            sid = int(matched.group('sid'))
            sids.add(sid)
            if sid in unsupported:
                continue
            contentVectors = defaultdict(list)
            for pattern in self._genericPattern.finditer(option):
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
                raw = option.find('rawbytes;') != -1
                if keyword in self._keywordsMap and self._keywordsMap[keyword][0]:
                    raw = raw or bool(self._keywordsMap[keyword][0])
                    keyword = self._keywordsMap[keyword][0]
                contentVectors[(keyword, raw)].append(thisContent)
            convertedStrings = {}
            handled = True
            for bucket, patterns in contentVectors.iteritems():
                try:
                    independentPatterns = self._get_independent_patterns(patterns)
                    if not self._independent and len(independentPatterns) > 1:
                        raise RuntimeError, "Can't handle multiple independent patterns per rule!"
                    convertedStrings[bucket] = independentPatterns
                except RuntimeError, e:
                    unsupported.add(sid)
                    self._error_message('\nGetting pattern for rule with SID %d failed.\n%s\n'%(sid, str(e)))
                    handled = False
                    break
            if not handled:
                continue
            for keyword, patterns in convertedStrings.iteritems():
                keyword = keyword[0] + '_raw' if keyword[1] else keyword[0]
                try:
                    self._anml.add(keyword, sid, patterns)
                except AnmlException, e:
                    unsupported.add(sid)
                    self._error_message(str(e))
                #writeString = '%d: %s'%(sid, patterns[0])
                #if self._writeFiles and keyword not in outputFiles:
                    #outputFiles[keyword] = open(keyword + '.txt', 'wb')
                #if self._writeFiles:
                    #outputFiles[keyword].write(writeString + '\n')
                #else:
                    #print writeString
        return sids - unsupported, unsupported

    def export(self, directory, compile):
        if self._compile:
            self._anml.compile(directory)
        else:
            self._anml.export(directory)