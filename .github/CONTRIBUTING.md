# Contributing to BackVault

Thank you for your interest in contributing to BackVault! This document provides guidelines and instructions for contributing.

## Development Workflow

### Prerequisites

- Docker and Docker Compose
- Python 3.12+
- Git

### Local Development

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/backvault.git
   cd backvault
   ```

2. **Install development dependencies:**
   ```bash
   pip install -r requirements-dev.txt
   ```

3. **Run linting:**
   ```bash
   ruff check src/
   ruff format src/
   ```

4. **Build Docker image locally:**
   ```bash
   docker build -t backvault:dev .
   ```

5. **Test the image:**
   ```bash
   docker run --rm --security-opt seccomp=unconfined \
     -e BW_CLIENT_ID="test" \
     -e BW_CLIENT_SECRET="test" \
     -e BW_PASSWORD="test" \
     -e BW_SERVER="https://vault.test.com" \
     -e BW_FILE_PASSWORD="test" \
     backvault:dev
   ```

## Pull Request Process

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes:**
   - Follow existing code style
   - Add comments for complex logic
   - Update documentation as needed

3. **Test your changes:**
   - Build the Docker image
   - Run security scans locally
   - Test with actual Bitwarden instance if possible

4. **Commit your changes:**
   ```bash
   git add .
   git commit -m "Description of your changes"
   ```

5. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request:**
   - Go to GitHub and create a PR from your branch
   - Fill in the PR template
   - Wait for CI checks to pass
   - Address any review comments

## CI/CD Pipeline

### Automated Workflows

The project uses GitHub Actions for CI/CD:

#### 1. **Test Workflow** (`.github/workflows/test.yml`)
- Runs on every push and PR
- Lints code with Ruff
- Builds Docker image for testing
- Verifies image can start

#### 2. **Security Scan** (`.github/workflows/security-scan.yml`)
- Runs on push, PR, and weekly schedule
- Scans Docker image with Trivy
- Scans Python code with Bandit
- Uploads results to GitHub Security

#### 3. **Docker Publish** (`.github/workflows/docker-publish.yml`)
- Runs on merge to main or version tags
- Builds multi-architecture images (amd64, arm64, arm/v7)
- Publishes to GitHub Container Registry
- Tags appropriately (latest, version tags)

### Multi-Architecture Builds

Images are automatically built for:
- `linux/amd64` - x86_64 systems
- `linux/arm64` - ARM64 systems (Apple Silicon, AWS Graviton)
- `linux/arm/v7` - 32-bit ARM (Raspberry Pi)

## Release Process

### Creating a Release

1. **Update version number:**
   - Update `SECURITYASSESS.md` if needed
   - Update `README.md` if needed

2. **Create and push a version tag:**
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```

3. **GitHub Actions will automatically:**
   - Build multi-arch Docker images
   - Tag with version number and `latest`
   - Publish to GitHub Container Registry
   - Create GitHub release (if configured)

### Version Tagging Convention

Follow semantic versioning:
- **Major version** (v1.0.0): Breaking changes
- **Minor version** (v1.1.0): New features, backward compatible
- **Patch version** (v1.1.1): Bug fixes, backward compatible

### Docker Image Tags

Images are tagged as:
- `ghcr.io/yourusername/backvault:latest` - Latest main branch
- `ghcr.io/yourusername/backvault:v1.0.0` - Specific version
- `ghcr.io/yourusername/backvault:v1.0` - Minor version
- `ghcr.io/yourusername/backvault:v1` - Major version

## Code Style

### Python Code

- Follow PEP 8 style guide
- Use Ruff for linting and formatting
- Maximum line length: 100 characters
- Use type hints where appropriate

### Example:
```python
def example_function(param: str, count: int = 5) -> bool:
    """
    Brief description of the function.

    :param param: Description of param
    :param count: Description of count
    :return: Description of return value
    """
    return True
```

### Shell Scripts

- Use `set -euo pipefail` at the start
- Quote all variables: `"$VARIABLE"`
- Use long-form flags for readability: `--verbose` not `-v`

### Dockerfile

- Use multi-stage builds when appropriate
- Minimize layers
- Clean up in the same RUN command
- Pin versions for reproducibility

## Security Guidelines

### Security Best Practices

1. **Never commit secrets:**
   - Use `.env` files (already in `.gitignore`)
   - Use environment variables
   - Use GitHub secrets for CI/CD

2. **Input validation:**
   - Validate all user inputs
   - Use whitelists, not blacklists
   - Sanitize before logging

3. **Dependencies:**
   - Keep dependencies updated
   - Review security advisories
   - Use minimal base images

4. **Code review:**
   - All PRs require review
   - Security changes require extra scrutiny
   - Run security scans before merging

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email the maintainer privately
2. Include detailed description
3. Include steps to reproduce
4. Wait for response before public disclosure

## Testing

### Manual Testing Checklist

Before submitting a PR, test:

- [ ] Docker image builds successfully
- [ ] Container starts without errors
- [ ] Backup creation works
- [ ] Backup encryption works
- [ ] Cleanup works
- [ ] Retry logic works on failures
- [ ] Logs don't expose secrets

### Automated Tests

We use:
- **Ruff** for code linting
- **Bandit** for security scanning
- **Trivy** for container vulnerability scanning
- Docker build tests in CI

## Documentation

### What to Document

Update documentation when:
- Adding new features
- Changing configuration options
- Fixing bugs that affect users
- Changing security practices
- Updating dependencies

### Documentation Files

- `README.md` - User-facing documentation
- `SECURITYASSESS.md` - Security assessment
- `TROUBLESHOOTING.md` - Common issues
- This file - Contribution guidelines

## Getting Help

- **Questions:** Open a GitHub Discussion
- **Bugs:** Open a GitHub Issue
- **Security:** Email maintainer privately
- **Features:** Open a GitHub Issue with "enhancement" label

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Welcome newcomers
- Accept constructive criticism
- Focus on what's best for the community

### Unacceptable Behavior

- Harassment or discrimination
- Trolling or insulting comments
- Publishing private information
- Other unprofessional conduct

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 License.

---

Thank you for contributing to BackVault! 🚀
