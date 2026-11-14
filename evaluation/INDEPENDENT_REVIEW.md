# Independent label review — pending

No independent reviewer has yet approved these labels. The authoring agent created
and reviewed them; passing scanner tests does not substitute for separate review.

Review `cases.json` without consulting scanner predictions first. Check each snippet
against the rule definition, expected rule IDs, source locations (where specified),
and the written rationale. Do not execute the snippets. Record disagreements rather
than changing a label solely to improve the scanner score.

After actual independent review, set `review_status` to `independently_reviewed`,
supply a reviewer identifier in `reviewer`, record any corrections and their rationale,
and regenerate the reports. A reviewer can be a named teammate, instructor, or other
person who did not author the labels. No external message or review request has been sent.

| Case | Expected rule IDs | Independent sign-off |
| --- | --- | --- |
| `python_eval_positive` | PY-EVAL | Pending |
| `python_eval_negative` | none | Pending |
| `python_exec_positive` | PY-EXEC | Pending |
| `python_exec_negative` | none | Pending |
| `python_pickle_positive` | PY-PICKLE | Pending |
| `python_pickle_negative` | none | Pending |
| `python_yaml_positive` | PY-YAML | Pending |
| `python_yaml_negative` | none | Pending |
| `python_shell_positive` | PY-SHELL | Pending |
| `python_shell_negative` | none | Pending |
| `javascript_eval_positive` | JS-EVAL | Pending |
| `javascript_eval_negative` | none | Pending |
| `javascript_html_positive` | JS-INNERHTML | Pending |
| `javascript_html_negative` | none | Pending |
| `javascript_write_positive` | JS-DOCUMENT-WRITE | Pending |
| `javascript_write_negative` | none | Pending |
| `hardcoded_credential_positive` | HARDCODED-SECRET | Pending |
| `hardcoded_credential_negative` | none | Pending |
| `pickle_file` | PY-PICKLE | Pending |
| `yaml_safe_load` | none | Pending |
| `yaml_unqualified_safe_loader` | none | Pending |
| `eval_spacing` | PY-EVAL | Pending |
| `pickle_spacing` | PY-PICKLE | Pending |
| `javascript_write_spacing` | JS-DOCUMENT-WRITE | Pending |
| `javascript_typescript` | JS-EVAL | Pending |
| `javascript_jsx` | JS-INNERHTML | Pending |
| `javascript_tsx` | JS-DOCUMENT-WRITE | Pending |
| `python_rule_wrong_language` | none | Pending |
| `javascript_rule_wrong_language` | none | Pending |
| `global_credential_java` | HARDCODED-SECRET | Pending |
| `comment_false_positive` | none | Pending |
| `string_false_positive` | none | Pending |
| `javascript_comment_false_positive` | none | Pending |
| `yaml_multiline_safe_false_positive` | none | Pending |
| `pickle_alias_missed` | PY-PICKLE | Pending |
| `eval_line_continuation_missed` | PY-EVAL | Pending |
| `shell_multiline_value_missed` | PY-SHELL | Pending |
| `javascript_multiline_assignment_missed` | JS-INNERHTML | Pending |
| `sql_text_credential_false_positive` | PY-SQL-INJECTION | Pending |
| `sql_positive` | PY-SQL-INJECTION | Pending |
| `sql_negative` | none | Pending |
| `jsx_text_not_code` | none | Pending |
| `jsx_expression_code` | JS-EVAL | Pending |
| `tsx_expression_code` | JS-EVAL | Pending |
| `typescript_cast_call` | JS-EVAL | Pending |
| `typescript_generic_not_call` | none | Pending |
| `regex_after_if_block` | none | Pending |
| `regex_after_condition` | none | Pending |
| `division_call` | JS-EVAL | Pending |
| `javascript_shadowed_parameter` | none | Pending |
| `javascript_shadowed_var` | none | Pending |
| `javascript_block_shadow` | JS-EVAL | Pending |
| `javascript_destructured_binding` | none | Pending |
| `computed_innerhtml` | JS-INNERHTML | Pending |
| `python_pattern_binding` | none | Pending |
| `python_module_binding_order` | PY-EVAL | Pending |
| `python_nonlocal_import` | PY-PICKLE | Pending |
| `python_deferred_global_import` | PY-PICKLE | Pending |
| `sql_percent_format` | PY-SQL-INJECTION | Pending |
| `sql_string_format` | PY-SQL-INJECTION | Pending |
| `sql_concatenation` | PY-SQL-INJECTION | Pending |
| `sql_branch_merge` | PY-SQL-INJECTION | Pending |
| `sql_safe_reassignment` | none | Pending |
| `sql_parameter_argument_does_not_fix_interpolation` | PY-SQL-INJECTION | Pending |
| `sql_constant_concatenation` | none | Pending |
