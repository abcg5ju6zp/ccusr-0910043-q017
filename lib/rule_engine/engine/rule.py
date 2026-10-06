#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  rule_engine/engine/rule.py
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the project nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import decimal
from typing import Any, Iterable, Iterator, TYPE_CHECKING

from .. import authz
from .. import errors
from ..parser import Parser
from .context import Context

if TYPE_CHECKING:
    import graphviz

class Rule(object):
    """项目内部接口说明。"""
    parser: Parser = Parser()
    """
    The :py:class:`~rule_engine.parser.Parser` instance that will be used for parsing the rule text into a compatible
    用于规则求值的抽象语法树（AST）。
    """
    def __init__(self, text: str, context: Context | None = None, *, grants: Any = None) -> None:
        """项目内部接口说明。"""
        context = context or Context()
        self.text = text
        self.context = context
        self.statement = self.parser.parse(text, context)
        self.required_capabilities: frozenset = self.statement.required_capabilities
        """
        整条依赖链在编译期静态聚合出的所需能力集合。
        The capabilities the rule's whole dependency chain declares, aggregated at compile time. This is static
        metadata only — the authorization decision is never cached on the rule and is re-derived from the caller's
        grants on every evaluation.
        """
        # compile-time authorization: validate the dependency chain against the compiler's grants when they are
        # known (passed explicitly or configured on the context); evaluation always re-validates regardless
        effective_grants = grants if grants is not None else context.grants
        if effective_grants is not None:
            missing = self.required_capabilities - authz.grants_provider(effective_grants)()
            if missing:
                raise errors.CapabilityError(missing)

    def __getstate__(self) -> dict[str, Any]:
        return {'text': self.text, 'context': self.context}

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.text = state['text']
        self.context = state['context']
        self.statement = self.parser.parse(self.text, self.context)
        self.required_capabilities = self.statement.required_capabilities

    def __repr__(self) -> str:
        return "<{0} text={1!r} >".format(self.__class__.__name__, self.text)

    def __str__(self) -> str:
        return self.text

    def filter(self, things: Iterable[Any], *, grants: Any = None) -> Iterator[Any]:
        """项目内部接口说明。"""
        yield from (thing for thing in things if self.matches(thing, grants=grants))

    @classmethod
    def is_valid(cls, text: str, context: Context | None = None) -> bool:
        """项目内部接口说明。"""
        try:
            cls.parser.parse(text, (context or Context()))
        except errors.EngineError:
            return False
        return True

    def evaluate(self, thing: Any, *, grants: Any = None) -> Any:
        """项目内部接口说明。"""
        context = self.context
        previous_grants = context._tls.grants
        context._tls.reset()
        provider = authz.grants_provider(grants if grants is not None else context.grants)
        # execution-time authorization: re-validate the dependency chain against *this* caller's grants on every
        # evaluation so a cached rule can never reuse another tenant's authorization result
        missing = self.required_capabilities - provider()
        if missing:
            raise errors.CapabilityError(missing)
        context._tls.grants = provider
        try:
            with decimal.localcontext(context.decimal_context):
                return self.statement.evaluate(thing)
        finally:
            context._tls.grants = previous_grants

    def matches(self, thing: Any, *, grants: Any = None) -> bool:
        """项目内部接口说明。"""
        return bool(self.evaluate(thing, grants=grants))

    def to_graphviz(self) -> 'graphviz.Digraph':
        """项目内部接口说明。"""
        import graphviz
        digraph = graphviz.Digraph(comment=self.text)
        self.statement.to_graphviz(digraph)
        return digraph

class DebugRule(Rule):
    parser: Parser  # set per-instance in __init__ (overrides the class-level attribute on Rule)
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.parser = Parser(debug=True)
        super(DebugRule, self).__init__(*args, **kwargs)
