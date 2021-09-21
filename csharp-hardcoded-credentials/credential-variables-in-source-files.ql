/**
 * @name String literals assigned to credential variables
 * @description Find hardcoded credentials in source files
 * @kind problem
 * @problem.severity error
 * @precision low
 * @id cs/credential-variables-in-source-files
 * @tags security
 *       external/cwe/cwe-798
 */

import csharp

private class CredentialVar extends Assignable {
    pragma[noinline]
    CredentialVar() {
      exists(string name | name = this.getName() |
        name.regexpMatch("(?i).*pass(wd|word|code|phrase)(?!.*question).*")
      )
    }   
  }
  
  private class CredentialVariableAccess extends VariableAccess {
    pragma[noinline]
    CredentialVariableAccess() { this.getTarget() instanceof CredentialVar }
  }
  

from CredentialVar cv, StringLiteral sl
where cv.fromSource() and cv.getAnAssignedValue() = sl
select sl, "String literal assigned to a credential variable!"
