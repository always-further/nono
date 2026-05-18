# ETI npm Lifecycle Demo Script

ETI stands for Ephemeral Tool Isolation. The model is brokered, composable tool sandboxes for contextual chaining of commands.

A normal shell or agent session has ambient authority. If the agent can run npm, and npm can run node, and node can run sh, then a dependency install can quietly become arbitrary shell execution with the same filesystem, network, and environment access as the original session.

The same pattern shows up outside package managers. A cloud CLI may call a credential helper, a pager, a browser login flow, or a shell wrapper. kubectl may call an auth plugin, kustomize, helm, or a local exec credential provider. git may call ssh, gpg, a credential helper, hooks, or a diff tool. Build systems may call compilers, linkers, package managers, shell scripts, and test runners. The risk is not one specific tool; the risk is unbounded command chaining with inherited authority.

ETI changes that model. The parent session becomes a broker. Each tool invocation gets a short-lived sandbox with its own policy. When that tool tries to launch another tool, the broker evaluates the edge in context: who is calling, what command is being requested, what arguments are being used, and what capabilities that child should receive.

The policy is composable. We can say that an interactive session may run npm; npm may run node; but neither npm nor node may run sh. We can also say that kubectl may read one kubeconfig but not another, aws may use a staging profile but not inherited production credentials, or git may use ssh for fetch but not arbitrary shell hooks. Each edge in the chain can carry its own filesystem, network, credential, and environment scope.

Enforcement is still OS-backed. On macOS, nono uses Seatbelt sandboxing. On Linux, it uses Landlock and related kernel primitives where available. ETI is not just a warning layer over process creation; it is a broker that turns command-chain decisions into concrete sandbox capabilities for each child process.

That matters for AI agents because agents often need powerful tools, but those tools should not automatically inherit the agent's full authority. ETI lets us preserve useful workflows while narrowing the blast radius of tool behavior. The agent can still install dependencies, inspect repositories, run tests, query staging, or use cloud CLIs, but each tool interaction is mediated instead of becoming a free pass to the rest of the machine.

This demo is about supply-chain execution during package installation. Package managers do not just download files. They may execute lifecycle hooks such as postinstall, and those hooks usually run through a shell.

The goal is not to claim npm is bad. npm is just a clean example because the chain is easy to see: npm invokes node, and lifecycle execution goes through sh. The broader point is that install-time code execution is a real boundary. We can allow dependency resolution and package extraction while denying the shell hop used by lifecycle scripts.

The profile is intentionally small. The selected workdir is read-write because npm needs to read package.json and write node_modules and package-lock.json. The session can start npm, but not arbitrary tools. npm is allowed to launch node because npm itself is a Node program. npm and node are not allowed to launch sh.

The inherited environment is also reduced. Registry and GitHub tokens are stripped so they do not leak into the install process by accident. The npm cache is redirected to a demo cache path. For this demo, npm and the node process launched by npm get explicit registry network access. In production, that broad network grant would usually be replaced with a proxy or controlled egress policy.

The important part is the command graph. npm can use node, but npm and node cannot use sh. That means npm can function as a package manager, but lifecycle scripts that go through sh are stopped. In another profile, the graph might allow kubectl to call an exec auth plugin but only with a read-only production credential. In another, aws might be allowed to call a pager for read-only staging commands, while production mutation commands require approval. The model is the same: explicit edges, explicit capabilities.

Before installing anything, we inspect the package from the registry. It is a harmless package, but it has a real postinstall hook. We can see the lifecycle script in the registry metadata, list the package tarball, and preview the actual postinstall script body without installing it.

That package is intentionally benign. The point is that this code would normally be eligible to run during install. In a real supply-chain incident, this is one of the places attackers try to gain execution.

First, we run the safe path. We install the dependency but tell npm to ignore lifecycle scripts. The sandbox still allows npm to resolve and extract the package, and npm can show that the package is installed.

This demonstrates that ETI is not blocking npm as a package manager. It is controlling what npm can execute as a child process.

Then we run the same install without ignoring scripts. We enable foreground scripts so npm prints the lifecycle command it is about to run.

This is the key result. npm reaches the real package lifecycle hook. npm tries to run it through sh. ETI denies the shell hop before the package code runs.

The profile does not need to know this package by name. It enforces a general policy: npm may use node for npm's own operation, but npm and node may not use the shell. That same control applies to any package pulled into this install.

That is the useful property. We are not writing a signature for one known package. We are controlling the shape of the tool chain. The same style of policy can separate staging from production, allow git network fetches without granting shell hooks, or let a build tool invoke a compiler without allowing it to reach deployment credentials.

This is the model we want for agent tooling. The agent can use tools, but tools do not automatically inherit ambient authority. Each tool gets a narrow, auditable child policy. That gives us a practical way to let agents install dependencies, inspect code, run builds, invoke git, use kubectl, or call cloud CLIs while still mediating high-risk behavior such as shell execution, credential exposure, filesystem writes, or production access.

For production, we would keep the same command-graph idea: explicit allowed children, explicit filesystem scope, explicit environment handling, controlled network egress, and deny-by-default for risky hops.
