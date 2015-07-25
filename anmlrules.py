import micronap.sdk as ap
import exceptions
import os
import re
import sys

from builder import Builder

class AnmlException(exceptions.Exception):
    pass

class AnmlRules(object):
    def __init__(self):
        self._orAnchorPattern = re.compile(r'^\/(?P<before>.*)(?P<start>\(|\(.*?\|)\$(?P<end>\|.*?\)|\))(?P<after>(?:\)*))\/(?P<modifiers>.*)$')
        self._anchorPattern = re.compile(r'^\/(?P<open>(?:\(\?\w*:)?)(?P<start>\^?)(?P<pattern>.*?)(?<!\\)(?P<end>\$?)(?P<close>(?:\)*))\/(?P<modifiers>.*)$')
        self.reset()

    def reset(self):
        self._anmlNetworks = {}
        self._counter = 0

    def _next_boolean_id(self):
        self._counter += 1
        return '__boolean_%d__'%(self._counter)

    def _latch_with_boolean(self, network, element, boolean):
        ste = network.AddSTE('*')
        network.AddAnmlEdge(ste, boolean, ap.AnmlDefs.PORT_IN)
        network.AddAnmlEdge(element, boolean, ap.AnmlDefs.PORT_IN)
        network.AddAnmlEdge(element, ste, ap.AnmlDefs.PORT_IN)
        network.AddAnmlEdge(ste, ste, ap.AnmlDefs.PORT_IN)

    def _add_single_pattern(self, network, pattern, negation, reportCode = None):
        matched = self._anchorPattern.match(pattern)
        kwargs = {'startType' : ap.AnmlDefs.START_OF_DATA if matched.group('start') else ap.AnmlDefs.ALL_INPUT}
        if not negation and reportCode is not None and not matched.group('end'):
            kwargs.update({'reportCode' : reportCode, 'match' : True})
        try:
            pattern = '/' + matched.group('open') + matched.group('pattern') + matched.group('close') + '/' + matched.group('modifiers')
            regex = network.AddRegex(pattern, **kwargs)
        except ap.ApError, e:
            if 'back reference' in str(e):
                print pattern
                matched = re.match(r'^\/(?P<pattern>.*)\/(?P<modifiers>[ismexADSUXuJ]*)$', pattern)
                changed = ''
                try:
                    changed = '/' + Builder().replace(matched.group('pattern')) + '/' + matched.group('modifiers')
                    print changed
                    print '\n\n'
                except re.sre_parse.error:
                    pass
                try:
                    network.AddRegex(changed, **kwargs)
                except ap.ApError, e:
                    print 'Still no luck. :('
                    pass
            raise AnmlException, '\nAdding pattern "%s" failed.\n%s\n'%(pattern, str(e))
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

    def _add_multiple_patterns(self, network, patterns):
        elements = []
        for pattern, negation in patterns:
            regex, latch = self._add_single_pattern(network, pattern, negation)
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

    def add(self, keyword, sid, patterns):
        if keyword not in self._anmlNetworks:
            anml = ap.Anml()
            network = anml.CreateAutomataNetwork(anmlId = keyword)
            self._anmlNetworks[keyword] = (anml, network)
        else:
            network = self._anmlNetworks[keyword][1]

        if len(patterns) == 1:
            pattern, negation = patterns[0]
            matched = self._match_or_anchor(pattern)
            if matched is not None:
                before, altPattern, after, modifiers = matched
                pattern = '/' + before + after + '/' + modifiers
                regex, latch = self._add_single_pattern(network, pattern, negation)
                boolean = network.AddBoolean(mode = ap.BooleanMode.OR, anmlId = self._next_boolean_id(),
                                             match = True, reportCode = sid, eod = True)
                network.AddAnmlEdge(regex, boolean, ap.AnmlDefs.PORT_IN)
                pattern = '/' + before + altPattern + after + '/' + modifiers

            self._add_single_pattern(network, pattern, negation, reportCode = sid)
        else:
            for index in xrange(len(patterns)):
                pattern, negation = patterns[index]
                matched = self._match_or_anchor(pattern)
                if matched is not None:
                    before, altPattern, after, modifiers = matched
                    patterns[index] = ('/' + before + '$' + after + '/' + modifiers, negation)
                    self.add(keyword, sid, patterns)
                    patterns[index] = ('/' + before + altPattern + after + '/' + modifiers, negation)
                    self.add(keyword, sid, patterns)
                    break
            else:
                elements = self._add_multiple_patterns(network, patterns)
                boolean = network.AddBoolean(mode = ap.BooleanMode.AND, reportCode = sid, match = True, eod = True, anmlId = self._next_boolean_id())
                for element in elements:
                    network.AddAnmlEdge(element, boolean, ap.AnmlDefs.PORT_IN)

    def export(self, directory):
        for keyword, anmlNetwork in self._anmlNetworks.iteritems():
            anmlNetwork[1].ExportAnml(os.path.join(directory, keyword + '.anml'))

    def compile(self, directory):
        for keyword, anmlNetwork in self._anmlNetworks.iteritems():
            #if keyword != "general":
                #continue
            print 'Compiling %s\n'%(keyword)
            try:
                automata, emap = anmlNetwork[0].CompileAnml(options = ap.CompileDefs.AP_OPT_SHOW_DEBUG)
                automata.Save(os.path.join(directory, keyword + '.fsm'))
            except ap.ApError, e:
                sys.stderr.write('\nCompilation failed with the following error message.\n%s\n'%(str(e)))
                sys.stderr.flush()
