import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.security.Security

abstract class KapeConfig extends TaintTracking::Configuration {
  bindingset[this]
  KapeConfig() { any() }

  override predicate isSource(DataFlow::Node node) { isUserInput(node.asExpr(), _) }

  override predicate isAdditionalTaintStep(DataFlow::Node n1, DataFlow::Node n2) {
    n2.asExpr().(DotFieldAccess).getQualifier() = n1.asExpr()
  }
}
