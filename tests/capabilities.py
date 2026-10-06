#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  tests/capabilities.py
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

import dataclasses
import pickle
import types as pytypes
import unittest

import rule_engine
import rule_engine.engine as engine
import rule_engine.errors as errors
import rule_engine.types as types
from rule_engine.builtins import Builtins
from rule_engine.engine._attribute_resolver import _AttributeResolver

__all__ = ('CapabilityTests',)

ADMIN = {'admin:read'}

def _protected_function(value):
    return value * 2
_protected_function.__required_capabilities__ = {'admin:exec'}

@dataclasses.dataclass
class _Employee:
    name: str
    salary: float

class CapabilityTests(unittest.TestCase):
    def assertCapabilityDenied(self, rule, thing, missing=ADMIN, **evaluate_kwargs):
        with self.assertRaises(errors.CapabilityError) as ctx:
            rule.evaluate(thing, **evaluate_kwargs)
        self.assertEqual(ctx.exception.capabilities, frozenset(missing))
        return ctx.exception

    # declaration points
    def test_resolver_capabilities_mapping(self):
        context = engine.Context(resolver_capabilities={'salary': ADMIN})
        rule = engine.Rule('salary > 100', context=context)
        self.assertEqual(rule.required_capabilities, frozenset(ADMIN))
        self.assertCapabilityDenied(rule, {'salary': 200})
        self.assertTrue(rule.evaluate({'salary': 200}, grants=ADMIN))

    def test_resolver_capabilities_callable(self):
        context = engine.Context(resolver_capabilities=lambda name: ADMIN if name == 'salary' else None)
        rule = engine.Rule('salary > 100 and name == "luke"', context=context)
        self.assertEqual(rule.required_capabilities, frozenset(ADMIN))
        self.assertCapabilityDenied(rule, {'salary': 200, 'name': 'luke'})
        self.assertTrue(rule.evaluate({'salary': 200, 'name': 'luke'}, grants=ADMIN))

    def test_resolver_self_declared_capabilities(self):
        def resolver(thing, name):
            return thing[name]
        resolver.required_capabilities = {'salary': ADMIN}
        context = engine.Context(resolver=resolver)
        rule = engine.Rule('salary > 100', context=context)
        self.assertEqual(rule.required_capabilities, frozenset(ADMIN))
        self.assertCapabilityDenied(rule, {'salary': 200})
        self.assertTrue(rule.evaluate({'salary': 200}, grants=ADMIN))

    def test_resolver_capabilities_union_of_context_and_resolver(self):
        def resolver(thing, name):
            return thing[name]
        resolver.required_capabilities = {'bonus': {'hr:read'}}
        context = engine.Context(resolver=resolver, resolver_capabilities={'salary': ADMIN})
        self.assertEqual(engine.Rule('salary > 1', context=context).required_capabilities, frozenset(ADMIN))
        self.assertEqual(engine.Rule('bonus > 1', context=context).required_capabilities, frozenset({'hr:read'}))

    def test_builtin_capabilities(self):
        context = engine.Context()
        context.builtins = Builtins({'top_secret': lambda: 42}, capabilities={'top_secret': ADMIN})
        rule = engine.Rule('$top_secret() == 42', context=context)
        self.assertEqual(rule.required_capabilities, frozenset(ADMIN))
        self.assertCapabilityDenied(rule, {})
        self.assertTrue(rule.evaluate({}, grants=ADMIN))

    def test_derived_attribute_capabilities(self):
        resolver = _AttributeResolver()
        @resolver.attribute('test_protected_derived', types.DataType.STRING, result_type=types.DataType.FLOAT, capabilities=ADMIN)
        def _protected_derived(self, value):
            return len(value)
        self.addCleanup(_AttributeResolver.attribute.type_map[types.DataType.STRING].pop, 'test_protected_derived')
        rule = engine.Rule('name.test_protected_derived > 3', context=engine.Context())
        # the symbol type is undefined at compile time so the requirement is discovered dynamically at execution
        self.assertEqual(rule.required_capabilities, frozenset())
        self.assertCapabilityDenied(rule, {'name': 'abcd'})
        self.assertTrue(rule.evaluate({'name': 'abcd'}, grants=ADMIN))

    def test_derived_attribute_capabilities_static(self):
        resolver = _AttributeResolver()
        @resolver.attribute('test_protected_static', types.DataType.STRING, result_type=types.DataType.FLOAT, capabilities=ADMIN)
        def _protected_static(self, value):
            return len(value)
        self.addCleanup(_AttributeResolver.attribute.type_map[types.DataType.STRING].pop, 'test_protected_static')
        context = engine.Context(type_resolver={'name': types.DataType.STRING})
        rule = engine.Rule('name.test_protected_static > 3', context=context)
        self.assertEqual(rule.required_capabilities, frozenset(ADMIN))
        self.assertCapabilityDenied(rule, {'name': 'abcd'})
        self.assertTrue(rule.evaluate({'name': 'abcd'}, grants=ADMIN))

    def test_derived_attribute_on_literal_is_not_constant_folded(self):
        resolver = _AttributeResolver()
        @resolver.attribute('test_protected_literal', types.DataType.STRING, result_type=types.DataType.FLOAT, capabilities=ADMIN)
        def _protected_literal(self, value):
            return len(value)
        self.addCleanup(_AttributeResolver.attribute.type_map[types.DataType.STRING].pop, 'test_protected_literal')
        # the string literal is known at compile time; folding must not execute the protected attribute at parse time
        rule = engine.Rule('"abcd".test_protected_literal > 3', context=engine.Context())
        self.assertEqual(rule.required_capabilities, frozenset(ADMIN))
        self.assertCapabilityDenied(rule, {})
        self.assertTrue(rule.evaluate({}, grants=ADMIN))

    def test_object_type_attribute_capabilities(self):
        employee_type = types.DataType.OBJECT(
                'Employee',
                attributes={'name': types.DataType.STRING, 'salary': types.DataType.FLOAT},
                attribute_capabilities={'salary': ADMIN}
        )
        context = engine.Context(type_resolver={'employee': employee_type})
        rule = engine.Rule('employee.salary > 100', context=context)
        self.assertEqual(rule.required_capabilities, frozenset(ADMIN))
        thing = {'employee': _Employee(name='luke', salary=200)}
        self.assertCapabilityDenied(rule, thing)
        self.assertTrue(rule.evaluate(thing, grants=ADMIN))
        # unprotected attributes on the same object are unaffected
        self.assertTrue(engine.Rule('employee.name == "luke"', context=context).evaluate(thing))

    def test_object_type_attribute_capabilities_safe_navigation(self):
        employee_type = types.DataType.OBJECT(
                'Employee',
                attributes={'name': types.DataType.STRING, 'salary': types.DataType.FLOAT},
                attribute_capabilities={'salary': ADMIN}
        )
        context = engine.Context(type_resolver={'employee': types.DataType.NULLABLE(employee_type)})
        rule = engine.Rule('employee&.salary', context=context)
        self.assertEqual(rule.required_capabilities, frozenset(ADMIN))
        # the whole dependency chain is validated up front even though safe navigation on null would not touch the
        # attribute at runtime
        self.assertCapabilityDenied(rule, {'employee': None})
        self.assertIsNone(rule.evaluate({'employee': None}, grants=ADMIN))
        self.assertCapabilityDenied(rule, {'employee': _Employee(name='luke', salary=200)})
        self.assertEqual(rule.evaluate({'employee': _Employee(name='luke', salary=200)}, grants=ADMIN), 200)

    def test_function_value_capabilities(self):
        context = engine.Context(resolver=lambda thing, name: {'get_fn': _protected_function}[name])
        rule = engine.Rule('get_fn(21) == 42', context=context)
        self.assertCapabilityDenied(rule, {}, missing={'admin:exec'})
        self.assertTrue(rule.evaluate({}, grants={'admin:exec'}))

    def test_function_value_capabilities_nested_call(self):
        def factory():
            return _protected_function
        context = engine.Context(resolver=lambda thing, name: {'factory': factory}[name])
        rule = engine.Rule('factory()(21) == 42', context=context)
        self.assertCapabilityDenied(rule, {}, missing={'admin:exec'})
        self.assertTrue(rule.evaluate({}, grants={'admin:exec'}))

    def test_function_value_capabilities_as_argument(self):
        context = engine.Context(resolver=lambda thing, name: {'protected_fn': _protected_function}[name])
        rule = engine.Rule('$map(protected_fn, [1, 2])[0] == 2', context=context)
        self.assertCapabilityDenied(rule, {}, missing={'admin:exec'})
        self.assertTrue(rule.evaluate({}, grants={'admin:exec'}))

    def test_bound_method_capabilities(self):
        class Account(object):
            def admin_balance(self):
                return 200
        Account.admin_balance.__required_capabilities__ = ADMIN
        context = engine.Context(resolver=rule_engine.resolve_attribute)
        rule = engine.Rule('account.admin_balance() > 100', context=context)
        thing = pytypes.SimpleNamespace(account=Account())
        self.assertCapabilityDenied(rule, thing)
        self.assertTrue(rule.evaluate(thing, grants=ADMIN))

    # compile-time validation of the whole dependency chain
    def test_compile_time_check_with_rule_grants(self):
        context = engine.Context(resolver_capabilities={'salary': ADMIN})
        with self.assertRaises(errors.CapabilityError):
            engine.Rule('salary > 100', context=context, grants=set())
        rule = engine.Rule('salary > 100', context=context, grants=ADMIN)
        self.assertTrue(rule.evaluate({'salary': 200}, grants=ADMIN))

    def test_compile_time_check_with_context_grants(self):
        context = engine.Context(resolver_capabilities={'salary': ADMIN}, grants=set())
        with self.assertRaises(errors.CapabilityError):
            engine.Rule('salary > 100', context=context)
        context = engine.Context(resolver_capabilities={'salary': ADMIN}, grants=ADMIN)
        self.assertIsInstance(engine.Rule('salary > 100', context=context), engine.Rule)

    def test_dependency_chain_aggregation(self):
        employee_type = types.DataType.OBJECT(
                'Employee',
                attributes={'name': types.DataType.STRING, 'salary': types.DataType.FLOAT},
                attribute_capabilities={'salary': {'admin:read'}}
        )
        context = engine.Context(
                type_resolver={'employee': employee_type, 'bonus': types.DataType.FLOAT},
                resolver_capabilities={'bonus': {'hr:read'}}
        )
        rule = engine.Rule('employee.salary + bonus > 100', context=context)
        self.assertEqual(rule.required_capabilities, frozenset({'admin:read', 'hr:read'}))
        thing = {'employee': _Employee(name='luke', salary=50), 'bonus': 100}
        self.assertCapabilityDenied(rule, thing, missing={'admin:read', 'hr:read'})
        self.assertCapabilityDenied(rule, thing, grants={'admin:read'}, missing={'hr:read'})
        self.assertTrue(rule.evaluate(thing, grants={'admin:read', 'hr:read'}))

    def test_comprehension_variable_requires_no_capability(self):
        context = engine.Context(resolver_capabilities={'secrets': ADMIN})
        rule = engine.Rule('[x for x in secrets][0] == 1', context=context)
        self.assertEqual(rule.required_capabilities, frozenset(ADMIN))
        self.assertCapabilityDenied(rule, {'secrets': [1, 2]})
        self.assertTrue(rule.evaluate({'secrets': [1, 2]}, grants=ADMIN))
        rule = engine.Rule('[x for x in items][0] == 1', context=engine.Context())
        self.assertEqual(rule.required_capabilities, frozenset())
        self.assertTrue(rule.evaluate({'items': [1, 2]}))

    # cached rules must not reuse another caller's authorization
    def test_cached_rule_revalidates_per_caller(self):
        context = engine.Context(resolver_capabilities={'salary': ADMIN})
        rule = engine.Rule('salary > 100', context=context)
        thing = {'salary': 200}
        # tenant A is authorized
        self.assertTrue(rule.evaluate(thing, grants=ADMIN))
        # tenant B reuses the same cached rule object but not tenant A's authorization
        self.assertCapabilityDenied(rule, thing)
        self.assertCapabilityDenied(rule, thing, grants=set())
        # tenant A is still authorized afterwards (no denial state is cached either)
        self.assertTrue(rule.evaluate(thing, grants=ADMIN))

    def test_pickled_rule_still_enforces(self):
        context = engine.Context(resolver_capabilities={'salary': ADMIN})
        rule = pickle.loads(pickle.dumps(engine.Rule('salary > 100', context=context)))
        self.assertEqual(rule.required_capabilities, frozenset(ADMIN))
        self.assertCapabilityDenied(rule, {'salary': 200})
        self.assertTrue(rule.evaluate({'salary': 200}, grants=ADMIN))

    def test_context_pickle_preserves_capability_configuration(self):
        context = engine.Context(resolver_capabilities={'salary': ADMIN}, grants=ADMIN)
        context2 = pickle.loads(pickle.dumps(context))
        self.assertEqual(context2.grants, ADMIN)
        rule = engine.Rule('salary > 100', context=context2)
        self.assertEqual(rule.required_capabilities, frozenset(ADMIN))
        self.assertTrue(rule.evaluate({'salary': 200}))

    # dynamic resolution paths
    def test_dynamic_nested_mapping_field(self):
        context = engine.Context(resolver_capabilities={'salary': ADMIN})
        rule = engine.Rule('user.salary > 100', context=context)
        thing = {'user': {'salary': 200}}
        self.assertCapabilityDenied(rule, thing)
        self.assertTrue(rule.evaluate(thing, grants=ADMIN))

    def test_item_access_enforces_resolver_capabilities(self):
        context = engine.Context(resolver_capabilities={'salary': ADMIN})
        rule = engine.Rule('user["salary"] > 100', context=context)
        # a literal string key names the field statically, so the whole chain is covered at compile time
        self.assertEqual(rule.required_capabilities, frozenset(ADMIN))
        thing = {'user': {'salary': 200}}
        self.assertCapabilityDenied(rule, thing)
        self.assertTrue(rule.evaluate(thing, grants=ADMIN))

    def test_item_access_with_computed_key(self):
        context = engine.Context(resolver_capabilities={'salary': ADMIN})
        rule = engine.Rule('user[key] > 100', context=context)
        self.assertEqual(rule.required_capabilities, frozenset())
        thing = {'user': {'salary': 200}, 'key': 'salary'}
        self.assertCapabilityDenied(rule, thing)
        self.assertTrue(rule.evaluate(thing, grants=ADMIN))
        # keys without declarations resolve normally
        self.assertTrue(rule.evaluate({'user': {'other': 200}, 'key': 'other'}))

    def test_item_access_on_untyped_mapping(self):
        context = engine.Context(resolver_capabilities={'salary': ADMIN})
        rule = engine.Rule('user["salary"] > 100', context=context)
        self.assertCapabilityDenied(rule, {'user': {'salary': 200}})

    def test_invalid_capability_declaration_raises(self):
        with self.assertRaises(TypeError):
            engine.Rule('salary > 1', context=engine.Context(resolver_capabilities={'salary': 1}))
        with self.assertRaises(TypeError):
            engine.Rule('salary > 1', context=engine.Context(resolver_capabilities=123))

    def test_dynamic_attribute_on_untyped_symbol(self):
        resolver = _AttributeResolver()
        @resolver.attribute('test_dynamic_hidden', types.DataType.STRING, result_type=types.DataType.STRING, capabilities=ADMIN)
        def _dynamic_hidden(self, value):
            return value[::-1]
        self.addCleanup(_AttributeResolver.attribute.type_map[types.DataType.STRING].pop, 'test_dynamic_hidden')
        rule = engine.Rule('name.test_dynamic_hidden == "cba"', context=engine.Context())
        self.assertEqual(rule.required_capabilities, frozenset())
        self.assertCapabilityDenied(rule, {'name': 'abc'})
        self.assertTrue(rule.evaluate({'name': 'abc'}, grants=ADMIN))

    # short-circuit branches
    def test_short_circuit_static_chain_is_fully_validated(self):
        context = engine.Context(resolver_capabilities={'secret': ADMIN})
        rule = engine.Rule('false and secret', context=context)
        self.assertEqual(rule.required_capabilities, frozenset(ADMIN))
        self.assertCapabilityDenied(rule, {'secret': 1})
        # with the capability granted the untaken branch performs no access
        self.assertFalse(rule.evaluate({'secret': 1}, grants=ADMIN))

    def test_short_circuit_dynamic_branch(self):
        resolver = _AttributeResolver()
        @resolver.attribute('test_sc_hidden', types.DataType.STRING, result_type=types.DataType.STRING, capabilities=ADMIN)
        def _sc_hidden(self, value):
            return value
        self.addCleanup(_AttributeResolver.attribute.type_map[types.DataType.STRING].pop, 'test_sc_hidden')
        rule = engine.Rule('flag and name.test_sc_hidden', context=engine.Context())
        # the untaken branch performs no access and raises nothing
        self.assertFalse(rule.evaluate({'flag': False, 'name': 'abc'}))
        # the taken branch is authorized dynamically at access time
        self.assertCapabilityDenied(rule, {'flag': True, 'name': 'abc'})
        self.assertTrue(rule.evaluate({'flag': True, 'name': 'abc'}, grants=ADMIN))

    def test_ternary_static_chain_is_fully_validated(self):
        context = engine.Context(resolver_capabilities={'secret': ADMIN})
        rule = engine.Rule('flag ? secret : 0', context=context)
        self.assertEqual(rule.required_capabilities, frozenset(ADMIN))
        self.assertCapabilityDenied(rule, {'flag': False, 'secret': 1})
        self.assertEqual(rule.evaluate({'flag': False, 'secret': 1}, grants=ADMIN), 0)

    # permissions revoked mid-execution
    def test_grants_revoked_mid_execution_mutable_set(self):
        grants = set(ADMIN)
        def revoking_resolver(thing, name):
            grants.discard('admin:read')
            return thing[name]
        context = engine.Context(resolver=revoking_resolver, resolver_capabilities={'first': ADMIN, 'second': ADMIN})
        rule = engine.Rule('first and second', context=context)
        # the static pre-check passes, then the resolver revokes the grant before 'second' is resolved
        self.assertCapabilityDenied(rule, {'first': True, 'second': True}, grants=grants)

    def test_grants_revoked_mid_execution_callable(self):
        state = {'grants': set(ADMIN)}
        def revoking_resolver(thing, name):
            state['grants'] = set()
            return thing[name]
        context = engine.Context(resolver=revoking_resolver, resolver_capabilities={'first': ADMIN, 'second': ADMIN})
        rule = engine.Rule('first and second', context=context)
        self.assertCapabilityDenied(rule, {'first': True, 'second': True}, grants=lambda: state['grants'])

    def test_callable_grants_provider(self):
        state = {'grants': set(ADMIN)}
        context = engine.Context(resolver_capabilities={'salary': ADMIN})
        rule = engine.Rule('salary > 100', context=context)
        self.assertTrue(rule.evaluate({'salary': 200}, grants=lambda: state['grants']))
        state['grants'] = set()
        self.assertCapabilityDenied(rule, {'salary': 200}, grants=lambda: state['grants'])

    # denial results must not leak protected fields
    def test_capability_error_message_only_names_categories(self):
        context = engine.Context(resolver_capabilities={'top_secret_field': ADMIN})
        rule = engine.Rule('top_secret_field == 1', context=context)
        error = self.assertCapabilityDenied(rule, {'top_secret_field': 1})
        self.assertIn('admin:read', error.message)
        self.assertNotIn('top_secret_field', error.message)

    def test_capability_error_message_object_attribute(self):
        employee_type = types.DataType.OBJECT(
                'Employee',
                attributes={'name': types.DataType.STRING, 'top_secret_field': types.DataType.FLOAT},
                attribute_capabilities={'top_secret_field': ADMIN}
        )
        context = engine.Context(type_resolver={'employee': employee_type})
        rule = engine.Rule('employee.top_secret_field == 1', context=context)
        error = self.assertCapabilityDenied(rule, {'employee': _Employee(name='luke', salary=1)})
        self.assertIn('admin:read', error.message)
        self.assertNotIn('top_secret_field', error.message)

    def test_capability_error_is_evaluation_error(self):
        self.assertTrue(issubclass(errors.CapabilityError, errors.EvaluationError))
        context = engine.Context(resolver_capabilities={'salary': ADMIN}, grants=set())
        with self.assertRaises(errors.EngineError):
            engine.Rule('salary > 1', context=context)

    # grants plumbing
    def test_matches_and_filter_accept_grants(self):
        context = engine.Context(resolver_capabilities={'salary': ADMIN})
        rule = engine.Rule('salary > 100', context=context)
        things = [{'salary': 200}, {'salary': 50}]
        self.assertEqual(list(rule.filter(things, grants=ADMIN)), [{'salary': 200}])
        self.assertTrue(rule.matches(things[0], grants=ADMIN))
        with self.assertRaises(errors.CapabilityError):
            list(rule.filter(things))

    def test_context_grants_used_by_default(self):
        context = engine.Context(resolver_capabilities={'salary': ADMIN}, grants=ADMIN)
        rule = engine.Rule('salary > 100', context=context)
        self.assertTrue(rule.evaluate({'salary': 200}))
        # explicit grants for one evaluation do not replace the context default
        self.assertCapabilityDenied(rule, {'salary': 200}, grants=set())
        self.assertTrue(rule.evaluate({'salary': 200}))

    def test_unprotected_rules_are_unaffected(self):
        rule = engine.Rule('name == "luke" and age > 20', context=engine.Context())
        self.assertEqual(rule.required_capabilities, frozenset())
        self.assertTrue(rule.evaluate({'name': 'luke', 'age': 30}))
        self.assertFalse(rule.evaluate({'name': 'luke', 'age': 10}))
