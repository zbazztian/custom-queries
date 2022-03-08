/**
 * @name Errors When Double Free
 * @description Freeing a previously allocated resource twice can lead to various vulnerabilities in the program.
 * @kind problem
 * @id cpp/double-free-custom
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-415
 */

import cpp

predicate between(ControlFlowNode a, ControlFlowNode mid, ControlFlowNode b) {
  notThroughX(a, mid, b) and notThroughX(mid, b, a)
}

predicate notThroughX(ControlFlowNode e1, ControlFlowNode e2, ControlFlowNode X) {
  e1 = e2
  or
  exists(ControlFlowNode cfn | cfn = e1.getASuccessor() and cfn != X and notThroughX(cfn, e2, X))
}

from FunctionCall fc, FunctionCall fc2, LocalScopeVariable v
where
  freeCall(fc, v.getAnAccess()) and
  freeCall(fc2, v.getAnAccess()) and
  fc != fc2 and
  not exists(Expr exptmp |
    (exptmp = v.getAnAssignedValue() or exptmp.(AddressOfExpr).getOperand() = v.getAnAccess()) and
    between(fc, exptmp, fc2)
  ) and
  not exists(FunctionCall fctmp |
    not fctmp instanceof DeallocationExpr and
    between(fc, fctmp, fc2) and
    fctmp.getAnArgument().(VariableAccess).getTarget() = v
  ) and
  (
    fc.getTarget().hasGlobalOrStdName("realloc") and
    (
      not fc.getParent*() instanceof IfStmt and
      not exists(IfStmt iftmp |
        iftmp.getCondition().getAChild*().(VariableAccess).getTarget().getAnAssignedValue() = fc
      )
    )
    or
    not fc.getTarget().hasGlobalOrStdName("realloc")
  )
select fc2.getArgument(0),
  "This pointer may have already been cleared in the line " + fc.getLocation().getStartLine() + "."
