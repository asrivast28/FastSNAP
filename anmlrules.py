import micronap.sdk as ap
import exceptions
import os
import re
import sys

from parser import RegexParser

class AnmlException(exceptions.Exception):
    pass

class AnmlRules(object):
    def __init__(self, maxStes, backreferences):
        self._maxStes = maxStes
        self._backreferences = backreferences
        self._anmlNetworks = {}
        self._counter = 0
        if self._backreferences:
            self._backreferenceSids = set()
            self._backreferenceFile = open('backreferences.txt', 'wb')

        self._orAnchorPattern = re.compile(r'^\/(?P<before>.*)(?P<start>\(|\(.*?\|)\$(?P<end>\|.*?\)|\))(?P<after>(?:\)*))\/(?P<modifiers>.*)$')
        self._anchorPattern = re.compile(r'^\/(?P<open>(?:\(\?\w*:)?)(?P<start>\^?)(?P<pattern>.*?)(?<!\\)(?P<end>\$?)(?P<close>(?:\)*))\/(?P<modifiers>.*)$')
        self._genericPattern = re.compile(r'^\/(?P<pattern>.*)\/(?P<modifiers>[ismexADSUXuJ]*)$')

    def _next_boolean_id(self):
        self._counter += 1
        return '__boolean_%d__'%(self._counter)

    def _latch_with_boolean(self, network, element, boolean):
        ste = network.AddSTE('*')
        network.AddAnmlEdge(ste, boolean, ap.AnmlDefs.PORT_IN)
        network.AddAnmlEdge(element, boolean, ap.AnmlDefs.PORT_IN)
        network.AddAnmlEdge(element, ste, ap.AnmlDefs.PORT_IN)
        network.AddAnmlEdge(ste, ste, ap.AnmlDefs.PORT_IN)

    def _replace_back_references(self, pattern):
        matched = self._genericPattern.match(pattern)
        changed = None
        try:
            changed = RegexParser(matched.group('pattern')).replace_groups()
            changed = '/' + changed + '/' + matched.group('modifiers')
        except:
            changedPattern, subCount = re.subn(r'\(\?<(\w+)>', lambda x : r'(?P<%s>'%x.group(1), pattern)
            if subCount > 0:
                return self._replace_back_references(changedPattern)
            raise
        else:
            return changed

    def _add_single_pattern(self, network, pattern, negation, sid, reportCode = None):
        matched = self._anchorPattern.match(pattern)
        kwargs = {'startType' : ap.AnmlDefs.START_OF_DATA if matched.group('start') else ap.AnmlDefs.ALL_INPUT}
        if not negation and reportCode is not None and not matched.group('end'):
            kwargs.update({'reportCode' : reportCode, 'match' : True})
        try:
            pattern = '/' + matched.group('open') + matched.group('pattern') + matched.group('close') + '/' + matched.group('modifiers')
            if self._backreferences and sid in self._backreferenceSids:
                try:
                    changed = self._replace_back_references(pattern)
                except re.sre_parse.error:
                    pass
                else:
                    pattern = changed
            regex = network.AddRegex(pattern, **kwargs)
        except ap.ApError, e:
            error = True
            msg = str(e)
            if self._backreferences and e.code == -112:
                try:
                    changed = self._replace_back_references(pattern)
                except re.sre_parse.error, f:
                    msg = 'RegexParser Error: %s'%str(f)
                else:
                    try:
                        regex = network.AddRegex(changed, **kwargs)
                    except ap.ApError, f:
                        msg = str(f)
                    else:
                        self._backreferenceFile.write('%d: %s\n'%(sid, pattern))
                        self._backreferenceSids.add(sid)
                        error = False
            if error:
                raise AnmlException, '\nAdding pattern "%s" for rule with SID %d failed.\n%s\n'%(pattern, sid, msg)
        if matched.group('end') and reportCode is not None:
            kwargs = {'mode' : ap.BooleanMode.OR, 'anmlId' : self._next_boolean_id(), 'eod' : True}
            if reportCode is not None:
                kwargs.update({'reportCode' : reportCode, 'match' : True})
            boolean = network.AddBoolean(**kwargs)
            network.AddAnmlEdge(regex, boolean, ap.AnmlDefs.PORT_IN)
            return (boolean, False)
        if not negation:
            if matched.group('end'):
                return (regex, reportCode is not None)
            else:
                return (regex, True)
        else:
            kwargs = {'mode' : ap.BooleanMode.NOR, 'anmlId' : self._next_boolean_id()}
            if reportCode is not None:
                kwargs.update({'reportCode' : reportCode, 'match' : True, 'eod' : True})
            boolean = network.AddBoolean(**kwargs)
            self._latch_with_boolean(network, regex, boolean)
            return (boolean, True)

    def _add_multiple_patterns(self, network, patterns, sid):
        elements = []
        for pattern, negation in patterns:
            regex, latch = self._add_single_pattern(network, pattern, negation, sid)
            if negation or not latch:
                elements.append(regex)
            else:
                boolean = network.AddBoolean(mode = ap.BooleanMode.OR, anmlId = self._next_boolean_id())
                self._latch_with_boolean(network, regex, boolean)
                elements.append(boolean)
        return elements

    def _match_or_anchor(self, pattern):
        matched = self._orAnchorPattern.match(pattern)
        if matched is not None:
            altPattern = []
            for first, second in re.findall(r'(.*?)(\||\))', matched.group('start') + matched.group('end')):
                alt = first[1:] if first.startswith('(') else first
                if alt:
                    altPattern.append(alt)
            altPattern = altPattern[0] if len(altPattern) == 1 else '(' + '|'.join(altPattern) + ')'
            return matched.group('before'), altPattern, matched.group('after'), matched.group('modifiers')

    def _add_patterns(self, network, sid, patterns):
        if len(patterns) == 1:
            pattern, negation = patterns[0]
            matched = self._match_or_anchor(pattern)
            if matched is not None:
                before, altPattern, after, modifiers = matched
                pattern = '/' + before + after + '/' + modifiers
                regex, latch = self._add_single_pattern(network, pattern, negation, sid)
                boolean = network.AddBoolean(mode = ap.BooleanMode.OR, anmlId = self._next_boolean_id(),
                                             match = True, reportCode = sid, eod = True)
                network.AddAnmlEdge(regex, boolean, ap.AnmlDefs.PORT_IN)
                pattern = '/' + before + altPattern + after + '/' + modifiers

            self._add_single_pattern(network, pattern, negation, sid, reportCode = sid)
        else:
            for index in xrange(len(patterns)):
                pattern, negation = patterns[index]
                matched = self._match_or_anchor(pattern)
                if matched is not None:
                    before, altPattern, after, modifiers = matched
                    patterns[index] = ('/' + before + '$' + after + '/' + modifiers, negation)
                    self._add_patterns(network, sid, patterns)
                    patterns[index] = ('/' + before + altPattern + after + '/' + modifiers, negation)
                    self._add_patterns(network, sid, patterns)
                    break
            else:
                elements = self._add_multiple_patterns(network, patterns, sid)
                boolean = network.AddBoolean(mode = ap.BooleanMode.AND, reportCode = sid, match = True, eod = True, anmlId = self._next_boolean_id())
                for element in elements:
                    network.AddAnmlEdge(element, boolean, ap.AnmlDefs.PORT_IN)

    def add(self, keyword, sid, patterns):
        # try to add the pattern to a dummy anml object first
        # this will throw an error, if there are any issues with patterns
        anml = ap.Anml()
        network = anml.CreateAutomataNetwork()
        self._add_patterns(network, sid, patterns)

        # check if the rule satisfies the maximum STEs limit
        if self._maxStes > 0:
            automaton, emap = anml.CompileAnml(ap.CompileDefs.AP_OPT_NO_PLACE_AND_ROUTE)
            info = automaton.GetInfo()
            if info.ste_count > self._maxStes:
                keyword = '%s_%d'%(keyword, sid)

        # create a new network if it doesn't exist
        if keyword not in self._anmlNetworks:
            anml = ap.Anml()
            network = anml.CreateAutomataNetwork(anmlId = keyword)
            self._anmlNetworks[keyword] = (anml, network)
        else:
            network = self._anmlNetworks[keyword][1]

        # now add pattern to the network
        self._add_patterns(network, sid, patterns)


    def export(self, directory):
        for keyword, anmlNetwork in self._anmlNetworks.iteritems():
            anmlNetwork[1].ExportAnml(os.path.join(directory, keyword + '.anml'))

    def compile(self, directory):
        for keyword, anmlNetwork in self._anmlNetworks.iteritems():
            #if 'general' not in keyword:
                #continue
            print '\nCompiling %s\n'%keyword
            try:
                automata, emap = anmlNetwork[0].CompileAnml(options = ap.CompileDefs.AP_OPT_SHOW_DEBUG)
                automata.Save(os.path.join(directory, keyword + '.fsm'))
            except ap.ApError, e:
                sys.stderr.write('\nCompilation failed with the following error message.\n%s\n'%(str(e)))
                sys.stderr.flush()
            print '\nDone.\n'
