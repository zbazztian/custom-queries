/**
 * @name Unclear validation of array index
 * @description Accessing an array without first checking
 *              that the index is within the bounds of the array can
 *              cause undefined behavior and can also be a security risk.
 * @kind path-problem
 * @id cpp/unclear-array-index-validation
 * @problem.severity warning
 * @security-severity 8.8
 * @tags security
 *       external/cwe/cwe-129
 */

import cpp
import semmle.code.cpp.controlflow.Guards
private import semmle.code.cpp.rangeanalysis.RangeAnalysisUtils
import Kape
import DataFlow::PathGraph

predicate hasUpperBound(VariableAccess offsetExpr) {
  exists(BasicBlock controlled, StackVariable offsetVar, SsaDefinition def |
    controlled.contains(offsetExpr) and
    linearBoundControls(controlled, def, offsetVar) and
    offsetExpr = def.getAUse(offsetVar)
  )
}

pragma[noinline]
predicate linearBoundControls(BasicBlock controlled, SsaDefinition def, StackVariable offsetVar) {
  exists(GuardCondition guard, boolean branch |
    guard.controls(controlled, branch) and
    cmpWithLinearBound(guard, def.getAUse(offsetVar), Lesser(), branch)
  )
}

class Config extends KapeConfig {
  Config() { this = "CustomImproperArrayIndexValidation" }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() = any(ArrayExpr ae).getArrayOffset()
  }
}

from Config config, DataFlow::PathNode source, DataFlow::PathNode sink
where
  config.hasFlowPath(source, sink) and
  not hasUpperBound(sink.getNode().asExpr())
select sink, source, sink,
  "$@ flows to here and is used in an array indexing expression, potentially causing an invalid access.",
  source, "User-provided value"
