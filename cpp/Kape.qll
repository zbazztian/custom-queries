import semmle.code.cpp.pointsto.PointsTo
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.security.Security

private class InterestingAddressOfExpr extends PointsToExpr {
  InterestingAddressOfExpr() { this instanceof AddressOfExpr }

  override predicate interesting() { this instanceof AddressOfExpr }
}

abstract class KapeConfig extends TaintTracking::Configuration {
  bindingset[this]
  KapeConfig() { any() }

  override predicate isSource(DataFlow::Node node) { isUserInput(node.asExpr(), _) }

  override predicate isAdditionalTaintStep(DataFlow::Node n1, DataFlow::Node n2) {
    n1.asExpr().(PointsToExpr).pointsTo().(Variable).getAnAccess() = n2.asExpr() and
    n2.asExpr().getAPredecessor*() = n1.asExpr()
    or
    n2.asExpr().(DotFieldAccess).getQualifier() = n1.asExpr()
  }
}
