"""运行项目 README 声明的核心回归测试。"""

from importlib import import_module


engine = import_module("tests.engine")
parser = import_module("tests.parser")
security = import_module("tests.security")
thread_safety = import_module("tests.thread_safety")


EngineTests = engine.EngineTests
EngineRuleTests = engine.EngineRuleTests
EngineDatetimeRuleTests = engine.EngineDatetimeRuleTests
ContextTests = engine.ContextTests
ObjectTypeTests = engine.ObjectTypeTests
ContextSerializationTests = engine.ContextSerializationTests
ParserTests = parser.ParserTests
ParserLeftOperatorRightTests = parser.ParserLeftOperatorRightTests
ParserLiteralTests = parser.ParserLiteralTests
ThreadSafetyTests = thread_safety.ThreadSafetyTests

# 多租户能力鉴权安全回归测试
CapabilityDeclarationTests = security.CapabilityDeclarationTests
CompileTimeDenialTests = security.CompileTimeDenialTests
RuntimeEnforcementTests = security.RuntimeEnforcementTests
RuleCacheIsolationTests = security.RuleCacheIsolationTests
TenantIsolationTests = security.TenantIsolationTests
ErrorMessageTests = security.ErrorMessageTests
UnsecuredModeTests = security.UnsecuredModeTests
SecuritySerializationTests = security.SecuritySerializationTests
