import micronap.sdk as ap
import exceptions
import os
import sys


class AnmlException(exceptions.Exception):
    pass

class AnmlRules(object):
    def __init__(self):
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
        kwargs = {'startType' : ap.AnmlDefs.ALL_INPUT}
        if not negation and reportCode is not None:
            kwargs.update({'reportCode' : reportCode, 'match' : True})
        try:
            regex = network.AddRegex(pattern, **kwargs)
        except ap.ApError, e:
            raise AnmlException, '\nAdding pattern "%s" failed.\n%s\n'%(pattern, str(e))
        if not negation:
           return regex
        else:
            kwargs = {'mode' : ap.BooleanMode.NOR, 'anmlId' : self._next_boolean_id()}
            if reportCode is not None:
                kwargs.update({'reportCode' : reportCode, 'match' : True, 'eod' : True})
            boolean = network.AddBoolean(**kwargs)
            self._latch_with_boolean(network, regex, boolean)
            return boolean

    def _add_multiple_patterns(self, network, patterns):
        elements = []
        for pattern, negation in patterns:
            regex = self._add_single_pattern(network, pattern, negation)
            if negation:
                elements.append(regex)
            else:
                boolean = network.AddBoolean(mode = ap.BooleanMode.OR, anmlId = self._next_boolean_id())
                self._latch_with_boolean(network, regex, boolean)
                elements.append(boolean)
        return elements 

    def add(self, keyword, sid, patterns):
        if keyword not in self._anmlNetworks:
            anml = ap.Anml()
            network = anml.CreateAutomataNetwork(anmlId = keyword)
            self._anmlNetworks[keyword] = (anml, network) 
        if len(patterns) == 1:
            pattern, negation = patterns[0]
            self._add_single_pattern(self._anmlNetworks[keyword][1], pattern, negation, reportCode = sid)
        else:
            network = self._anmlNetworks[keyword][1]
            elements = self._add_multiple_patterns(network, patterns)
            boolean = network.AddBoolean(reportCode = sid, match = True, eod = True, anmlId = self._next_boolean_id())
            for element in elements:
                network.AddAnmlEdge(element, boolean, ap.AnmlDefs.PORT_IN) 

    def export(self, directory):
        for keyword, anmlNetwork in self._anmlNetworks.iteritems():
            anmlNetwork[1].ExportAnml(os.path.join(directory, keyword + '.anml'))

    def compile(self, directory):
        for keyword, anmlNetwork in self._anmlNetworks.iteritems():
            if keyword != "general":
                continue
            print 'Compiling %s\n'%(keyword)
            try:
                automata, emap = anmlNetwork[0].CompileAnml(options = ap.CompileDefs.AP_OPT_SHOW_DEBUG)
                automata.Save(os.path.join(directory, keyword + '.fsm'))
            except ap.ApError, e:
                sys.stderr.write('\nCompilation failed with the following error message.\n%s\n'%(str(e)))
                sys.stderr.flush()
