##
# @file rulesanml.py
# @author Ankit Srivastava <asrivast@gatech.edu>
#
# Copyright 2018 Georgia Institute of Technology
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import micronap.sdk as ap
import exceptions
import os
import re
import sys

from regexparser import RegexParser

class AnmlException(exceptions.Exception):
    pass

class RulesAnml(object):
    """
    Class for storing ANML-NFAs corresponding to the Snort rules.
    """
    def __init__(self, directory, maxStes = 0, maxRepeats = 0, backreferences = False):
        self._maxStes = maxStes
        self._maxRepeats = maxRepeats
        self._backreferences = backreferences
        self._anmlNetworks = {}
        self._counter = 0

        if self._maxRepeats > 0:
            self._repetitionSids = set()
            self._repetitionFile = open(os.path.join(directory, 'repetitions.txt'), 'wb')

        if self._backreferences:
            self._backreferenceSids = set()
            self._backreferenceFile = open(os.path.join(directory, 'backreferences.txt'), 'wb')

        self._orAnchorPattern = re.compile(r'^\/(?P<before>.*)(?P<start>\(|\(.*?\|)\$(?P<end>\|.*?\)|\))(?P<after>(?:\)*))\/(?P<modifiers>\w*)$')
        self._anchorPattern = re.compile(r'^\/(?P<open>(?:\(\?\w*:)?)(?P<start>\^?)(?P<pattern>.*?)(?<!\\)(?P<end>\$?)(?P<close>(?:\)*))\/(?P<modifiers>\w*)$')
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

    def _replace_bounded_repetitions(self, pattern, maxRepeats):
        matched = self._genericPattern.match(pattern)
        changed = RegexParser(matched.group('pattern')).replace_repeats(maxRepeats)
        if changed is not None:
            changed = '/' + changed + '/' + matched.group('modifiers')
        return changed

    def _add_negative_dependent(self, network, regex, dependent, reportCode):
        expression, depth = dependent
        exprRegex = network.AddRegex(expression)
        depthRegex = network.AddRegex('/.{%d}/'%depth)
        rangeRegex = network.AddRegex('/.{1,%d}/'%(depth - 1))
        network.AddAnmlEdge(regex, exprRegex)
        network.AddAnmlEdge(regex, depthRegex)
        network.AddAnmlEdge(regex, rangeRegex)

        counter = network.AddCounter(1, mode = ap.CounterMode.STOP_HOLD)
        network.AddAnmlEdgeEx(exprRegex, 0, counter, ap.AnmlDefs.COUNT_ONE_PORT)
        network.AddAnmlEdgeEx(depthRegex, 0, counter, ap.AnmlDefs.COUNT_ONE_PORT)
        network.AddAnmlEdgeEx(regex, 0, counter, ap.AnmlDefs.RESET_PORT)

        kwargs = {'mode' : ap.BooleanMode.AND, 'anmlId' : self._next_boolean_id()}
        if reportCode is not None:
            kwargs.update({'match' : True, 'reportCode' : reportCode})
        mainAnd = network.AddBoolean(**kwargs)
        network.AddAnmlEdge(depthRegex, mainAnd)
        network.AddAnmlEdge(counter, mainAnd)

        booleanOr = network.AddBoolean(mode = ap.BooleanMode.OR, anmlId = self._next_boolean_id())
        network.AddAnmlEdge(regex, booleanOr)
        network.AddAnmlEdge(rangeRegex, booleanOr)

        booleanNot = network.AddBoolean(mode = ap.BooleanMode.NOT, anmlId = self._next_boolean_id())
        network.AddAnmlEdge(counter, booleanNot)

        kwargs = {'mode' : ap.BooleanMode.AND, 'anmlId' : self._next_boolean_id()}
        if reportCode is not None:
            kwargs.update({'eod' : True, 'match' : True, 'reportCode' : reportCode})
        eodAnd = network.AddBoolean(**kwargs)
        network.AddAnmlEdge(booleanNot, eodAnd)
        network.AddAnmlEdge(booleanOr, eodAnd)

        return mainAnd, eodAnd

    def _add_single_pattern(self, network, pattern, negation, dependent, sid, reportCode = None):
        matched = self._anchorPattern.match(pattern)
        kwargs = {'startType' : ap.AnmlDefs.START_OF_DATA if matched.group('start') else ap.AnmlDefs.ALL_INPUT}
        if not negation and reportCode is not None and not matched.group('end') and not dependent:
            kwargs.update({'reportCode' : reportCode, 'match' : True})
        pattern = '/' + matched.group('open') + matched.group('pattern') + matched.group('close') + '/' + matched.group('modifiers')
        if self._backreferences and sid in self._backreferenceSids:
            try:
                changed = self._replace_back_references(pattern)
            except re.sre_parse.error:
                pass
            else:
                pattern = changed
        if self._maxRepeats > 0:
            try:
                changed = self._replace_bounded_repetitions(pattern, self._maxRepeats)
                if changed is not None:
                    if sid not in self._repetitionSids:
                        self._repetitionFile.write('%d: %s\n'%(sid, pattern))
                        self._repetitionSids.add(sid)
                    pattern = changed
            except:
                pass
        try:
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
        if dependent:
            main, eod = self._add_negative_dependent(network, regex, dependent, reportCode)
            return [(main, True), (eod, False)]
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
        for pattern, negation, dependent in patterns:
            returned = self._add_single_pattern(network, pattern, negation, dependent, sid)
            returned = [returned] if not isinstance(returned, list) else returned
            for element, latch in returned:
                if negation or not latch:
                    elements.append(element)
                else:
                    boolean = network.AddBoolean(mode = ap.BooleanMode.OR, anmlId = self._next_boolean_id())
                    self._latch_with_boolean(network, element, boolean)
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
            pattern, negation, dependent = patterns[0]
            matched = self._match_or_anchor(pattern)
            if matched is not None:
                before, altPattern, after, modifiers = matched
                pattern = '/' + before + after + '/' + modifiers
                regex, latch = self._add_single_pattern(network, pattern, negation, dependent, sid)
                boolean = network.AddBoolean(mode = ap.BooleanMode.OR, anmlId = self._next_boolean_id(),
                                             match = True, reportCode = sid, eod = True)
                network.AddAnmlEdge(regex, boolean, ap.AnmlDefs.PORT_IN)
                pattern = '/' + before + altPattern + after + '/' + modifiers

            self._add_single_pattern(network, pattern, negation, dependent, sid, reportCode = sid)
        else:
            for index in xrange(len(patterns)):
                pattern, negation, dependent = patterns[index]
                matched = self._match_or_anchor(pattern)
                if matched is not None:
                    before, altPattern, after, modifiers = matched
                    patterns[index] = ('/' + before + '$' + after + '/' + modifiers, negation, dependent)
                    self._add_patterns(network, sid, patterns)
                    patterns[index] = ('/' + before + altPattern + after + '/' + modifiers, negation, dependent)
                    self._add_patterns(network, sid, patterns)
                    break
            else:
                elements = self._add_multiple_patterns(network, patterns, sid)
                boolean = network.AddBoolean(mode = ap.BooleanMode.AND, reportCode = sid, match = True, eod = True, anmlId = self._next_boolean_id())
                for element in elements:
                    network.AddAnmlEdge(element, boolean, ap.AnmlDefs.PORT_IN)

    def add(self, keyword, sid, patterns):
        """
        Add the given patterns, identified by the sid, to the bucket corresponding to the keyword.
        """
        # try to add the pattern to a dummy anml object first
        # this will throw an error, if there are any issues with patterns
        anml = ap.Anml()
        network = anml.CreateAutomataNetwork()
        self._add_patterns(network, sid, patterns)

        # check if the rule satisfies the maximum STEs limit
        automaton, emap = anml.CompileAnml()
        info = automaton.GetInfo()
        if info.ste_count > 49152 / 2:
            raise AnmlException, '\nAdding patterns for rule with SID %d failed.\nRequired resources exceeded those in one half-core.\n'%sid
        bucket = keyword
        if self._maxStes > 0:
            if info.ste_count > self._maxStes:
                bucket = '%s_%d'%(keyword, sid)
        if info.clock_divisor > 1:
            bucket = '%s_%d'%(keyword, info.clock_divisor)
            #print keyword, sid, info.clock_divisor

        # create a new network if it doesn't exist
        if bucket not in self._anmlNetworks:
            anml = ap.Anml()
            network = anml.CreateAutomataNetwork(anmlId = bucket)
            self._anmlNetworks[bucket] = (anml, network)
        else:
            network = self._anmlNetworks[bucket][1]

        # now add pattern to the network
        self._add_patterns(network, sid, patterns)


    def export(self, directory):
        """
        Write out all the ANML-NFAs to the given directory.
        """
        for bucket, anmlNetwork in self._anmlNetworks.iteritems():
            anmlNetwork[1].ExportAnml(os.path.join(directory, bucket + '.anml'))

    def compile(self, directory):
        """
        Compile all the ANML-NFAs and write the AP-FSMs to the given directory.
        """
        for bucket, anmlNetwork in self._anmlNetworks.iteritems():
            #if 'general' not in keyword:
                #continue
            print '\nCompiling %s\n'%bucket
            try:
                automata, emap = anmlNetwork[0].CompileAnml()
                info = automata.GetInfo()
                print 'Clock divisor', info.clock_divisor
                automata.Save(os.path.join(directory, bucket + '.fsm'))
            except ap.ApError, e:
                sys.stderr.write('\nCompilation failed with the following error message.\n%s\n'%(str(e)))
                sys.stderr.flush()
            print '\nDone.\n'
