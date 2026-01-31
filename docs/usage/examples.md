# Examples

Common usage patterns and recipes for nono.

## AI Coding Agents

### Claude Code

Run Claude Code with access limited to your project:

```bash
nono --allow . -- claude
```

Allow Claude to read your global config:

```bash
nono --allow . --read-file ~/.claude/config.json -- claude
```

### Generic AI Agent

```bash
nono --allow ./workspace --net-allow -- my-ai-agent
```

## Build Tools

### Cargo (Rust)

```bash
# Full build with all access
nono --allow . -- cargo build

# Read source, write only to target
nono --read ./src --read ./Cargo.toml --read ./Cargo.lock --allow ./target -- cargo build
```

### npm/Node.js

```bash
# Install dependencies (needs network)
nono --allow . --net-allow -- npm install

# Run build (no network needed)
nono --allow . -- npm run build

# Run tests
nono --allow . -- npm test
```

### Make

```bash
nono --allow . -- make
```

## Network Operations

### curl/wget

```bash
# Download a file
nono --write ./downloads --net-allow -- curl -o ./downloads/file.tar.gz https://example.com/file.tar.gz

# API request
nono --allow . --net-allow -- curl -X POST https://api.example.com/data
```

### Git Operations

```bash
# Clone requires network
nono --allow ./repos --net-allow -- git clone https://github.com/user/repo.git

# Local operations don't need network
nono --allow . -- git status
nono --allow . -- git commit -m "message"

# Push/pull need network
nono --allow . --net-allow -- git push
```

## Multi-Directory Access

### Separate Source and Output

```bash
nono --read ./src --allow ./dist -- webpack build
```

### Multiple Projects

```bash
nono --allow ./project-a --allow ./project-b -- my-tool
```

### Shared Dependencies

```bash
nono --allow . --read ~/.local/share/my-tool -- my-tool
```

## Debugging and Testing

### Dry Run

Preview what access would be granted:

```bash
nono --allow . --read /etc --net-allow --dry-run -- my-agent
```

### Verbose Output

```bash
# Maximum verbosity
nono -vvv --allow . -- command
```

### Testing Sandbox Enforcement

```bash
# Should succeed - writing to allowed path
nono --allow . -- sh -c "echo test > ./allowed.txt"

# Should fail - writing outside allowed path
nono --allow . -- sh -c "echo test > /tmp/blocked.txt"

# Should fail - network blocked by default
nono --allow . -- curl https://example.com
```

## Shell Scripts

### Running a Script

```bash
nono --allow . -- ./my-script.sh
```

### Inline Commands

```bash
nono --allow . -- sh -c "echo hello && ls -la"
```

## Configuration Files

### Read-Only Config

```bash
nono --allow . --read-file ~/.config/myapp/config.toml -- myapp
```

### Multiple Config Files

```bash
nono --allow . \
  --read-file ~/.gitconfig \
  --read-file ~/.npmrc \
  -- my-tool
```

## Real-World Scenarios

### Code Review Agent

An agent that reads code and writes review comments:

```bash
nono \
  --read ./src \
  --read ./tests \
  --write ./reviews \
  --net-allow \
  -- code-review-agent
```

### Documentation Generator

An agent that reads source and generates docs:

```bash
nono \
  --read ./src \
  --allow ./docs \
  -- doc-generator
```

### Data Processing Pipeline

```bash
nono \
  --read ./input \
  --write ./output \
  --read-file ./config.yaml \
  -- data-processor
```
