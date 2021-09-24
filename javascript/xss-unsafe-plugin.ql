/**
 * @name Cross-site scripting vulnerable plugin
 * @kind path-problem
 * @id js/xss-unsafe-plugin
 */

import javascript
import DataFlow::PathGraph

class Configuration extends TaintTracking::Configuration {
  Configuration() { this = "XssUnsafeJQueryPlugin" }

  override predicate isSource(DataFlow::Node source) {
    source = jquery()
          .getAPropertyRead("fn")
          .getAPropertySource()
          .(DataFlow::FunctionNode)
          .getLastParameter()
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(JQuery::MethodCall call | call.interpretsArgumentAsHtml(sink))
  }

  override predicate isAdditionalTaintStep(DataFlow::Node src, DataFlow::Node sink) {
    exists(DataFlow::ClassNode cn, string p |
      cn.getAnInstanceReference().getAPropertyWrite(p).getRhs() = src and
      cn.getAnInstanceReference().getAPropertyRead(p) = sink
    )
  }
}

from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential XSS vulnerability in plugin."
