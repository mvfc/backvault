# GitHub Actions Setup Guide

This guide explains how to configure GitHub Actions for automated Docker image building and publishing.

## Prerequisites

- GitHub repository for your BackVault fork
- GitHub account with access to the repository

## Automatic Setup (Recommended)

The workflows are already configured! When you push to the `main` branch, GitHub Actions will automatically:

1. ✅ Build Docker images for multiple architectures
2. ✅ Run security scans
3. ✅ Publish to GitHub Container Registry
4. ✅ Tag with version numbers

## Configuration Steps

### 1. Enable GitHub Actions

1. Go to your repository on GitHub
2. Click **Settings** → **Actions** → **General**
3. Ensure "Allow all actions and reusable workflows" is selected
4. Click **Save**

### 2. Configure Package Permissions

For publishing to GitHub Container Registry (ghcr.io):

1. Go to **Settings** → **Actions** → **General**
2. Scroll to "Workflow permissions"
3. Select "Read and write permissions"
4. Check "Allow GitHub Actions to create and approve pull requests"
5. Click **Save**

### 3. (Optional) Enable GitHub Package Registry

1. Go to your repository **Settings**
2. Scroll to "Features"
3. Ensure "Packages" is enabled

### 4. Make Your Repository Public (or Configure Package Visibility)

**Option A: Public Repository (Recommended)**
- Images will be publicly accessible
- Anyone can pull the images
- No authentication required

**Option B: Private Repository**
1. Images will be private by default
2. To pull images, users need a Personal Access Token (PAT)
3. Configure in **Settings** → **Packages** → Package settings → "Change visibility"

## First Build

### Trigger Your First Workflow

**Method 1: Push to Main Branch**
```bash
git add .
git commit -m "feat: initial commit with CI/CD"
git push origin main
```

**Method 2: Manual Trigger**
1. Go to **Actions** tab on GitHub
2. Select "Build and Publish Docker Images"
3. Click "Run workflow"
4. Select branch (main)
5. Click "Run workflow"

### Monitor the Build

1. Go to **Actions** tab
2. Click on the running workflow
3. Watch the build progress
4. Check for any errors

Build typically takes 10-15 minutes for multi-architecture builds.

## Verify Published Images

After successful build:

1. Go to your repository homepage
2. Look for **Packages** section on the right side
3. Click on `backvault` package
4. You should see tags: `latest`, `main`, etc.

### Pull Your Image

```bash
# Replace 'yourusername' with your GitHub username
docker pull ghcr.io/yourusername/backvault:latest

# Verify it works
docker run --rm ghcr.io/yourusername/backvault:latest bw --version
```

## Creating Releases

### Semantic Versioning

To create a versioned release:

```bash
# Create a version tag
git tag -a v1.0.0 -m "Release v1.0.0 - Initial release"

# Push the tag
git push origin v1.0.0
```

This will trigger a build with tags:
- `ghcr.io/yourusername/backvault:latest`
- `ghcr.io/yourusername/backvault:v1.0.0`
- `ghcr.io/yourusername/backvault:v1.0`
- `ghcr.io/yourusername/backvault:v1`

### Release Notes

After pushing a tag, GitHub will automatically:
1. Build and publish the versioned images
2. You can manually create a GitHub Release with notes

To create a release:
1. Go to **Releases** on GitHub
2. Click "Create a new release"
3. Select your tag
4. Write release notes
5. Publish release

## (Optional) Docker Hub Publishing

To also publish to Docker Hub:

### 1. Create Docker Hub Account & Token

1. Go to https://hub.docker.com
2. Sign up or log in
3. Go to **Account Settings** → **Security** → **New Access Token**
4. Create a token with "Read, Write, Delete" permissions
5. Copy the token

### 2. Add GitHub Secrets

1. Go to your repository **Settings** → **Secrets and variables** → **Actions**
2. Click "New repository secret"
3. Add two secrets:
   - Name: `DOCKERHUB_USERNAME`, Value: Your Docker Hub username
   - Name: `DOCKERHUB_TOKEN`, Value: Your Docker Hub token

### 3. Uncomment Docker Hub Steps

Edit `.github/workflows/docker-publish.yml`:

```yaml
# Uncomment these lines:
- name: Log in to Docker Hub
  if: github.event_name != 'pull_request'
  uses: docker/login-action@v3
  with:
    registry: ${{ env.REGISTRY_DOCKERHUB }}
    username: ${{ secrets.DOCKERHUB_USERNAME }}
    password: ${{ secrets.DOCKERHUB_TOKEN }}
```

And update the metadata section:
```yaml
images: |
  ${{ env.REGISTRY_GHCR }}/${{ env.IMAGE_NAME }}
  ${{ env.REGISTRY_DOCKERHUB }}/${{ secrets.DOCKERHUB_USERNAME }}/backvault
```

## Troubleshooting

### Build Fails with "Permission Denied"

**Solution:**
1. Check workflow permissions in Settings → Actions
2. Ensure "Read and write permissions" is selected

### Can't Pull Image: "unauthorized"

**Solution:**
1. Image might be private - check package visibility
2. Or authenticate with GitHub:
   ```bash
   echo $GITHUB_TOKEN | docker login ghcr.io -u yourusername --password-stdin
   ```

### Multi-Arch Build Takes Too Long

**Normal behavior:**
- First build: 15-20 minutes (no cache)
- Subsequent builds: 5-10 minutes (with cache)

**To speed up:**
- Builds are cached automatically
- Each platform builds in parallel

### Build Fails: "QEMU not found"

**This shouldn't happen** - QEMU is set up automatically by the workflow.

If it does:
- Check `.github/workflows/docker-publish.yml` has `setup-qemu-action`
- Verify the workflow file is properly formatted

### Security Scan Finds Vulnerabilities

**Expected:**
- Trivy may find vulnerabilities in base images
- Most are not exploitable in this context
- Check the Security tab for details

**Action:**
1. Review the vulnerabilities
2. Update base image if needed
3. Update dependencies: `pip install --upgrade -r requirements.txt`

### Workflow Not Triggering

**Check:**
1. Workflow file syntax is correct
2. Pushing to `main` branch (not `master`)
3. Actions are enabled in Settings
4. Workflow file is in `.github/workflows/` directory

**Manual trigger:**
- Use "Run workflow" button in Actions tab

## Monitoring and Maintenance

### Regular Tasks

**Weekly:**
- Check Security scan results
- Review vulnerability reports

**Monthly:**
- Update dependencies
- Review and merge Dependabot PRs

**As Needed:**
- Create new releases for bug fixes or features
- Update Bitwarden CLI version in Dockerfile

### Best Practices

1. **Always test locally first:**
   ```bash
   docker build -t backvault:test .
   docker run --security-opt seccomp=unconfined backvault:test
   ```

2. **Use semantic versioning:**
   - Major: Breaking changes
   - Minor: New features
   - Patch: Bug fixes

3. **Write clear commit messages:**
   - `feat:` for features
   - `fix:` for bug fixes
   - `docs:` for documentation
   - `ci:` for CI/CD changes

4. **Keep workflows updated:**
   - GitHub Actions versions
   - Docker actions versions
   - Security scanning tools

## Getting Help

- **Workflow issues:** Check Actions tab → Failed workflow → Logs
- **Publishing issues:** Check Settings → Packages
- **Security issues:** Check Security tab → Code scanning alerts

For more help:
- GitHub Actions documentation: https://docs.github.com/actions
- Docker documentation: https://docs.docker.com/
- Open an issue in the repository

---

**Next Steps:**
1. Push your code to GitHub
2. Wait for the first build to complete
3. Pull your image and test it
4. Create your first release!

Happy building! 🚀
