/**
 * @name Overflow in uncontrolled allocation size
 * @description Allocating memory with a size controlled by an external
 *              user can result in integer overflow.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id cpp/uncontrolled-allocation-size
 * @tags reliability
 *       security
 *       external/cwe/cwe-190
 *       external/cwe/cwe-789
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.models.interfaces.Allocation
import DataFlow::PathGraph
import Kape

class Config extends KapeConfig {
  Config() { this = "TaintedAllocationSizeConfigCustom" }

  override predicate isSink(DataFlow::Node node) {
    exists(AllocationExpr ae | node.asExpr() = ae.getSizeExpr())
  }
}

from DataFlow::PathNode src, DataFlow::PathNode sink, Config conf
where conf.hasFlowPath(src, sink)
select sink, src, sink, "Tainted allocation size!"
