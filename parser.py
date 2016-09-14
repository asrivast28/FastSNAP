# This file modifies/builds on Xeger,
# which can be found at https://bitbucket.org/leapfrogdevelopment/rstr

import re

class RegexParser(object):
    """
    This class contains functionality for building a regular expression from
    the parsed result obtained by calling re.sre_parse.parse.
    """

    _categories = {
        'category_digit': r'\d',
        'category_not_digit': r'\D',
        'category_space' : r'\s',
        'category_not_space': r'\S',
        'category_word' : r'\w',
        'category_not_word' : r'\W',
    }

    _at = {
        'at_beginning_string' : r'\A',
        'at_beginning' : r'^',
        'at_end_string' : r'\Z',
        'at_end' : r'$',
    }

    def __init__(self, regex):
        self._parsed = re.sre_parse.parse(regex)
        self._repeat_bound = None
        self._cache = dict()
        self._cases = {
            'literal' : lambda x: re.escape(chr(x)),
            'not_literal' : lambda x: '[^%s]'%re.escape(chr(x)),
            'at' : lambda x: self._at[x],
            'in' : lambda x: '[%s]'%''.join(self._handle_state(i) for i in x),
            'any' : lambda x: '.',
            'range' : lambda x: '%c-%c'%x,
            'category' : lambda x: self._categories[x],
            'branch' : lambda x: self._handle_branch(x[1]),
            'subpattern' : lambda x: self._handle_group(x),
            'assert' : lambda x: '(?=%s)'%''.join(self._handle_state(i) for i in x[1]),
            'assert_not' : lambda x: '(?!%s)'%''.join(self._handle_state(i) for i in x[1]),
            'groupref' : lambda x: self._cache[x],
            'max_repeat' : lambda x: self._handle_repeat(True, *x),
            'min_repeat' : lambda x: self._handle_repeat(False, *x),
            'negate' : lambda x: '^',
        }

    def replace_groups(self):
        """
        Builds and returns a regex in which all the back references
        are replaced by the referenced group.
        """
        newstr = []
        for state in self._parsed:
            newstr.append(self._handle_state(state))
        return ''.join(newstr)

    def replace_repeats(self, repeat_bound):
        """
        Builds and returns a regex in which all the bounded repetitions
        above the given threshold are replaced by unbounded repetitions.
        """
        self._repeat_bound = repeat_bound
        self._is_changed = False
        newstr = []
        for state in self._parsed:
            newstr.append(self._handle_state(state))
        return None if not self._is_changed else ''.join(newstr)

    def _handle_state(self, state):
        opcode, value = state
        return self._cases[opcode](value)

    def _handle_group(self, value):
        result = ''.join(self._handle_state(i) for i in value[1])
        if value[0]:
            self._cache[value[0]] = result
            result = '(%s)'%result
        else:
            result = '(?:%s)'%result
        return result

    def _handle_branch(self, branches):
        options = []
        for branch in branches:
            options.append(''.join(self._handle_state(state) for state in branch))
        return '|'.join(options)

    def _handle_repeat(self, greedy, start_range, end_range, value):
        result = [''.join(self._handle_state(i) for i in value)]
        if end_range == re.sre_parse.MAXREPEAT:
            if start_range == 0:
                result.append('*')
            elif start_range == 1:
                result.append('+')
            else:
                result.append('{%d,'%start_range)
        else:
            repeat = []
            repeat.append('{%d'%start_range)
            if end_range != start_range:
                repeat.append(',%d'%end_range)
            repeat.append('}')
            if self._repeat_bound is not None and ((start_range > self._repeat_bound) or ((end_range - start_range) > self._repeat_bound)):
                result.append('*')
                self._is_changed = True
            else:
                result.extend(repeat)
        if not greedy:
            result.append('?')
        return ''.join(result)
