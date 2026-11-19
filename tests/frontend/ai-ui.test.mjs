import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import vm from "node:vm";

// Exercise the actual renderer with a minimal DOM, without a browser dependency.
function renderer() {
  const elements = new Map();
  function element() {
    return {textContent: "", hidden: false, children: [], classList: {toggle() {}},
      append(child) { this.children.push(child); },
      replaceChildren() { this.children = []; },
      addEventListener() {}, setAttribute() {}, removeAttribute() {}};
  }
  const document = {
    querySelector(selector) {
      if (!elements.has(selector)) elements.set(selector, element());
      return elements.get(selector);
    },
    querySelectorAll() { return []; },
    createElement: element,
  };
  const context = vm.createContext({document, window: {addEventListener() {}}, location: {hash: "scan"},
    fetch: () => new Promise(() => {})});
  const script = readFileSync(new URL("../../app/static/app.js", import.meta.url), "utf8").replace(/^import .*;\n/gm, "");
  vm.runInContext(script, context);
  return {render: ai => context.renderAI(ai), get: id => document.querySelector(id)};
}

test("AI section explains disabled and missing server output instead of silently hiding", () => {
  const ui = renderer();
  ui.render({status: "disabled"});
  assert.equal(ui.get("#aiSection").hidden, false);
  assert.match(ui.get("#aiStatus").textContent, /off for this scan/);
  ui.render(undefined);
  assert.equal(ui.get("#aiSection").hidden, false);
  assert.match(ui.get("#aiStatus").textContent, /server returned no AI status/);
});

test("AI renderer shows generated descriptions as text and preserves failure warnings", () => {
  const ui = renderer();
  ui.render({status: "complete", model: "test:1", notice: "Review.", explanations: [
    {file: "a.js", line: 12, rule_id: "JS-EVAL", explanation: "<script>untrusted</script>", remediation: "Parse data.", limitation: "Check origin."},
  ]});
  assert.equal(ui.get("#aiResults").children.length, 1);
  const card = ui.get("#aiResults").children[0];
  assert.ok(card.children.some(child => child.textContent === "<script>untrusted</script>"));
  ui.render({status: "unavailable", warning: "Start Ollama.", notice: "Review."});
  assert.ok(ui.get("#aiResults").children.some(child => child.textContent === "Start Ollama."));
});
