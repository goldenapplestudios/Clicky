// ESLint flat config used by check_js_syntax.sh.
//
// The globals below are not a guess. They are the MEASURED contents of a
// workflow script's scope, obtained by running tests/syntax/probe-workflow-globals.js
// through the real workflow engine and reading back
// `Object.getOwnPropertyNames(globalThis)`. An earlier revision of this file
// was hand-written from memory and listed 28 names; the real surface is 71, so
// a workflow legitimately using `setTimeout`, `TypeError`, `Symbol`, `Reflect`
// or a typed array would have been rejected as broken.
//
// To refresh after a Claude Code upgrade changes the engine:
//     Workflow({scriptPath: "tests/syntax/probe-workflow-globals.js", args: ["probe"]})
// and regenerate the `globals` block below from its `globalThisOwnNames`.
// The probe spawns no agents and costs nothing.
//
// This file therefore doubles as executable documentation of the workflow
// engine's injected surface, and `no-undef` is what turns it into an enforced
// contract: a misspelled `pahse("Scan")` is valid syntax that would otherwise
// fail only at runtime, mid-engagement.
//
// Deliberately ABSENT, and confirmed absent by the same probe: `process`,
// `fetch`, `require`, `module`, `exports`, `Buffer`, `crypto`, `performance`,
// `setInterval`, `queueMicrotask`, `AbortController`, `atob`/`btoa`,
// `structuredClone`, `TextEncoder`/`TextDecoder`, `URL`/`URLSearchParams`.
// Using any of them in a workflow is a runtime crash, so `no-undef` catching
// them is the point - this is exactly how the live `process is not defined`
// bug in workflows/pentest-parallel.js was found.
//
// Note `Date` and `Math` ARE in scope, but the engine throws on `Date.now()`,
// argless `new Date()`, and `Math.random()` because they would break workflow
// resume (`new Date(0)` with an argument is fine). That is a runtime
// restriction, not a lint-able one, and is not enforced here.
export default [
  {
    files: ["**/*.mjs"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        // --- workflow engine surface ---
        agent: "readonly",
        args: "readonly",
        budget: "readonly",
        log: "readonly",
        parallel: "readonly",
        phase: "readonly",
        pipeline: "readonly",
        workflow: "readonly",
        // --- standard globals present in the sandbox ---
        AggregateError: "readonly",
        Array: "readonly",
        ArrayBuffer: "readonly",
        AsyncDisposableStack: "readonly",
        BigInt: "readonly",
        BigInt64Array: "readonly",
        BigUint64Array: "readonly",
        Boolean: "readonly",
        DataView: "readonly",
        Date: "readonly",
        DisposableStack: "readonly",
        Error: "readonly",
        EvalError: "readonly",
        Float16Array: "readonly",
        Float32Array: "readonly",
        Float64Array: "readonly",
        Function: "readonly",
        Infinity: "readonly",
        Int16Array: "readonly",
        Int32Array: "readonly",
        Int8Array: "readonly",
        Intl: "readonly",
        Iterator: "readonly",
        JSON: "readonly",
        Map: "readonly",
        Math: "readonly",
        NaN: "readonly",
        Number: "readonly",
        Object: "readonly",
        Promise: "readonly",
        Proxy: "readonly",
        RangeError: "readonly",
        ReferenceError: "readonly",
        Reflect: "readonly",
        RegExp: "readonly",
        Set: "readonly",
        String: "readonly",
        SuppressedError: "readonly",
        Symbol: "readonly",
        SyntaxError: "readonly",
        Temporal: "readonly",
        TypeError: "readonly",
        URIError: "readonly",
        Uint16Array: "readonly",
        Uint32Array: "readonly",
        Uint8Array: "readonly",
        Uint8ClampedArray: "readonly",
        WeakMap: "readonly",
        WeakSet: "readonly",
        clearTimeout: "readonly",
        console: "readonly",
        decodeURI: "readonly",
        decodeURIComponent: "readonly",
        encodeURI: "readonly",
        encodeURIComponent: "readonly",
        escape: "readonly",
        eval: "readonly",
        globalThis: "readonly",
        isFinite: "readonly",
        isNaN: "readonly",
        parseFloat: "readonly",
        parseInt: "readonly",
        setTimeout: "readonly",
      },
    },
    rules: {
      // The whole point: catch identifiers that do not exist in the sandbox.
      "no-undef": "error",
      // Cheap, unambiguous correctness checks adjacent to syntax.
      "no-dupe-keys": "error",
      "no-dupe-args": "error",
      "no-unreachable": "error",
      "no-const-assign": "error",
      "no-func-assign": "error",
      // Deliberately off: style and unused-variable noise are not this
      // check's job, and a workflow legitimately declares values it returns
      // rather than reads.
      "no-unused-vars": "off",
      "no-empty": "off",
    },
  },
];
