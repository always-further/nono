# nono ETI lifecycle demo package

This package exists to demonstrate npm install-time lifecycle execution under nono ETI.

It is intentionally harmless:

- no dependencies
- no network access
- no file writes
- no environment variable inspection
- no credential access

The package defines:

```json
{
  "scripts": {
    "postinstall": "node postinstall.js"
  }
}
```

npm runs lifecycle scripts through the platform shell. With the `demo-npm-supply-chain` nono profile, `npm` and selected `node` execution are allowed, but shell execution is denied. That lets the demo show a real npm lifecycle boundary without using a suspicious or destructive package.

## Local smoke test

```bash
npm test
```

Expected output:

```text
[nono-eti-lifecycle-demo] npm lifecycle hook executed.
This demo hook is intentionally harmless: no network, no file writes, no environment inspection.
Under nono ETI with shell execution denied, npm should be blocked before this script runs.
```

## Publish checklist

Review the files before publishing:

```bash
npm pack --dry-run
```

If the package name is available for your npm account:

```bash
npm publish --access public
```

If npm returns `404 Not Found` on publish, verify that you are logged in with `npm whoami`, that any required 2FA flow completed, and that the unscoped package name is available. If the name is unavailable or reserved, choose a unique unscoped name in `package.json`.

## Demo usage after publish

Fetch the real tarball outside nono:

```bash
npm pack nono-eti-lifecycle-demo@0.1.0
```

Install safely under nono with lifecycle scripts disabled:

```bash
printf '%s\n' '{"private":true,"dependencies":{"nono-eti-lifecycle-demo":"file:./nono-eti-lifecycle-demo-0.1.0.tgz"}}' > package.json
nono run --no-diagnostics --profile test-profiles/demo-npm-supply-chain.json -- npm install --ignore-scripts --cache /tmp/nono-demo/npm-cache --logs-dir /tmp/nono-demo/npm-cache/_logs
```

Then show ETI denying lifecycle execution:

```bash
rm -rf node_modules package-lock.json
nono run --no-diagnostics --profile test-profiles/demo-npm-supply-chain.json -- npm install --foreground-scripts --cache /tmp/nono-demo/npm-cache --logs-dir /tmp/nono-demo/npm-cache/_logs
```

Expected result: npm prints the lifecycle command, then nono denies the shell execution before `postinstall.js` runs.
