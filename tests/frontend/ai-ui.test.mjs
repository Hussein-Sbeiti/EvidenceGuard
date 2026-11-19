import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import vm from "node:vm";

// Exercise the actual renderer with a minimal DOM, without a browser dependency.
function renderer(aiStatus) {
  const elements = new Map();
  function element() {
    return {textContent: "", hidden: false, children: [], events: {}, classList: {toggle() {}},
      append(child) { this.children.push(child); },
      replaceChildren() { this.children = []; },
      before(other) { this.previous = other; }, after(other) { this.next = other; },
      addEventListener(name, callback) { this.events[name] = callback; }, setAttribute() {}, removeAttribute() {}};
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
    fetch: path => path === "/api/ai/status" ? Promise.resolve({ok: true, json: async () => aiStatus}) : new Promise(() => {})});
  const script = readFileSync(new URL("../../app/static/app.js", import.meta.url), "utf8").replace(/^import .*;\n/gm, "");
  vm.runInContext(script, context);
  return {render: ai => context.renderAI(ai), get: id => document.querySelector(id)};
}

test("AI section explains disabled and missing server output instead of silently hiding", () => {
  const ui = renderer();
  ui.render({status: "disabled"});
  assert.equal(ui.get("#aiSection").hidden, false);
  assert.match(ui.get("#aiStatus").textContent, /off for this scan/);
  assert.equal(ui.get("#codeFindings").open, true);
  assert.equal(ui.get("#codeFindings").next, ui.get("#aiSection"));
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
  assert.ok(card.children.some(child => child.children?.some(text => text.textContent === "<script>untrusted</script>")));
  assert.equal(ui.get("#codeFindings").open, false);
  assert.equal(ui.get("#codeFindings").previous, ui.get("#aiSection"));
  ui.render({status: "unavailable", warning: "Start Ollama.", notice: "Review."});
  assert.ok(ui.get("#aiResults").children.some(child => child.textContent === "Start Ollama."));
  assert.equal(ui.get("#codeFindings").open, true);
});

test("local AI check displays readiness without generating explanations", async () => {
  const ui = renderer({model: "local:1", status: "ready", message: "Installed; generation not tested."});
  await ui.get("#checkAI").events.click();
  assert.match(ui.get("#aiConnection").textContent, /local:1 · ready/);
  assert.match(ui.get("#aiConnection").textContent, /generation not tested/);
  assert.equal(ui.get("#checkAI").disabled, false);
  assert.equal(ui.get("#aiResults").children.length, 0);
});
