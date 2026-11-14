/* Intentionally insecure scanner fixture. Do not include in a real website.
 * Historical jQuery reference: CVE-2019-11358; affected-version review is
 * required. That advisory is relevant to the deepMerge example only.
 * No external dependencies or code are loaded by this fixture.
 */

function renderUntrustedHtml(element, userInput) {
  element.innerHTML = userInput;
}

function evaluateUntrustedInput(userInput) {
  return eval(userInput);
}

function writeUntrustedHtml(userInput) {
  document.write(userInput);
}

function deepMergeWithOldJQuery(jQuery, untrustedObject) {
  // Historical reproduction context: jQuery 3.3.1. Not a built-in scanner rule.
  return jQuery.extend(true, {}, untrustedObject);
}
