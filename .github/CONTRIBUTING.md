# Contributing to Hilbras Spectra

Thank you for your interest in contributing to Spectra.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<username>/spectra.git`
3. Install dependencies: `npm install`
4. Create a branch: `git checkout -b feature/my-feature`

## Development Guidelines

- Write TypeScript with strict mode enabled
- Follow existing code style (enforced by oxlint)
- Add tests for new functionality
- Update documentation for user-facing changes
- Keep the single-agent architecture — do not introduce multiple AI agents

## Commit Conventions

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add taint analysis cross-file support
fix: mask secrets in SARIF output
docs: update README benchmark section
test: add IDOR fixture e2e test
```

## Testing

```bash
npm test        # Run all tests
npm run lint    # Check linting
npm run build   # Verify build
```

All tests and lint checks must pass before a PR is accepted.

## Pull Requests

1. Update the README if you change behavior
2. Add tests for new features
3. Ensure CI passes
4. Describe the change in the PR body

## Security

See [SECURITY.md](./SECURITY.md) for reporting vulnerabilities.
