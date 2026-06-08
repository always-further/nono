#!/usr/bin/env node

"use strict";

const lines = [
  "[nono-eti-lifecycle-demo] npm lifecycle hook executed.",
  "This demo hook is intentionally harmless: no network, no file writes, no environment inspection.",
  "Under nono ETI with shell execution denied, npm should be blocked before this script runs."
];

console.log(lines.join("\n"));
