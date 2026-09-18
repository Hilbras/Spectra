# @hilbras/spectra

Modular, extensible, distributed security testing and analysis platform.

## Installation

```bash
npm install -g @hilbras/spectra
```

## Usage

```bash
spectra --version
spectra --help

# Create organization
spectra organization create "My Org" --slug my-org

# Add target
spectra target add "Example" --target-type domain --value example.com --project <id>

# Run scan
spectra scan run --target <id>

# View findings
spectra finding list
spectra finding stats
```

## What's Included

- Target management with scope enforcement
- Web crawling with robots.txt support
- 60+ technology fingerprinting rules
- SQL injection, XSS, and directory search scanners
- Evidence collection with redaction
- Finding verification with confidence scoring
- Plugin system with sandboxing

## Requirements

- Node.js 18+ (for installation)
- Linux or macOS (x64 or arm64)

## Documentation

- [GitHub](https://github.com/Hilbras/Spectra)
- [Architecture](https://github.com/Hilbras/Spectra/blob/main/docs/architecture/ARCHITECTURE.md)
- [Configuration](https://github.com/Hilbras/Spectra/blob/main/docs/CONFIGURATION.md)
- [API Reference](https://github.com/Hilbras/Spectra/blob/main/docs/API.md)

## License

AGPL-3.0
