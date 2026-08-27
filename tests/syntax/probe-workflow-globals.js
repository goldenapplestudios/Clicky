export const meta = {
  name: "probe-globals",
  description: "Enumerate the globals the workflow engine actually injects",
  phases: [],
};

// `typeof <undeclared>` is safe in JS - it yields "undefined" rather than
// throwing - so this probes each candidate without needing eval.
const declared = {
  agent: typeof agent,
  parallel: typeof parallel,
  pipeline: typeof pipeline,
  phase: typeof phase,
  log: typeof log,
  workflow: typeof workflow,
  args: typeof args,
  budget: typeof budget,
};

const builtins = {
  JSON: typeof JSON, Math: typeof Math, Date: typeof Date,
  Object: typeof Object, Array: typeof Array, String: typeof String,
  Number: typeof Number, Boolean: typeof Boolean, Set: typeof Set,
  Map: typeof Map, Promise: typeof Promise, Error: typeof Error,
  RegExp: typeof RegExp, Symbol: typeof Symbol, BigInt: typeof BigInt,
  WeakMap: typeof WeakMap, WeakSet: typeof WeakSet, Proxy: typeof Proxy,
  Reflect: typeof Reflect, Intl: typeof Intl,
  parseInt: typeof parseInt, parseFloat: typeof parseFloat,
  isNaN: typeof isNaN, isFinite: typeof isFinite,
  encodeURIComponent: typeof encodeURIComponent,
  decodeURIComponent: typeof decodeURIComponent,
  structuredClone: typeof structuredClone,
  TextEncoder: typeof TextEncoder, TextDecoder: typeof TextDecoder,
  URL: typeof URL, URLSearchParams: typeof URLSearchParams,
  Infinity: typeof Infinity, NaN: typeof NaN, undefined_: typeof undefined,
  globalThis: typeof globalThis,
};

const hostish = {
  console: typeof console, process: typeof process, fetch: typeof fetch,
  require: typeof require, module: typeof module, exports: typeof exports,
  Buffer: typeof Buffer, setTimeout: typeof setTimeout,
  setInterval: typeof setInterval, queueMicrotask: typeof queueMicrotask,
  AbortController: typeof AbortController, crypto: typeof crypto,
  performance: typeof performance, atob: typeof atob, btoa: typeof btoa,
};

let ownNames = [];
try { ownNames = Object.getOwnPropertyNames(globalThis).sort(); } catch (e) { ownNames = ["ERR:" + String(e)]; }

// The documented runtime restrictions - confirm they really do throw.
const restricted = {};
try { restricted.dateNow = typeof Date.now(); } catch (e) { restricted.dateNow = "THROWS: " + String(e).slice(0, 80); }
try { restricted.mathRandom = typeof Math.random(); } catch (e) { restricted.mathRandom = "THROWS: " + String(e).slice(0, 80); }
try { restricted.newDate = typeof new Date(); } catch (e) { restricted.newDate = "THROWS: " + String(e).slice(0, 80); }
try { restricted.newDateArg = typeof new Date(0); } catch (e) { restricted.newDateArg = "THROWS: " + String(e).slice(0, 80); }

return { declared, builtins, hostish, restricted, globalThisOwnNames: ownNames };
