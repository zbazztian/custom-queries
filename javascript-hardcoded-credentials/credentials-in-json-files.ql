/**
 * @name Credentials in JSON files
 * @description Find credentials in JSON files
 * @kind problem
 * @problem.severity error
 * @precision low
 * @id js/credentials-in-json-files
 * @tags security
 *       external/cwe/cwe-798
 */

import javascript

from JSONString js, string password
where password = js.getValue().regexpCapture("(?i).*pass(wd|word|code|phrase)(?!.*question)\\s*=\\s*([^;]+);.*", 2)
select js, "This JSON value contains the password \"" + password + "\""
