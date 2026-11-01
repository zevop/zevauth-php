# Releasing

Packagist publishes `zevauth/zevauth-php` straight from git tags, so a
release is a version bump and a tag. Nothing runs on your own machine
beyond the commit.

## Cutting a release

1. Set the new version in `src/Version.php` (`ZevAuth\Version::VERSION`)
   and add the changes to the README or changelog if they need saying.
   Commit and push to `main`, and let the **tests** workflow pass.
2. Tag and push the tag:

   ```sh
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

   Or on GitHub: **Releases → Draft a new release → Choose a tag**, type
   `v0.2.0`, target `main`, and publish. The workflow creates the release
   notes itself, so you can leave the description empty.

The **Release** workflow then checks the tag matches
`ZevAuth\Version::VERSION`, runs the tests and writes the GitHub Release
with generated notes. Packagist picks up the tag within a minute through
its GitHub hook.

If the version check fails, delete the tag (`git push --delete origin
v0.2.0`), fix `src/Version.php`, and tag again. Packagist only lists tags
it has seen; re-pushing a corrected tag is fine before anyone installs it.

## One-time setup

- **Packagist hook:** on packagist.org, open `zevauth/zevauth-php` →
  **Settings**, and confirm the GitHub hook shows as active. If it
  doesn't, connect your GitHub account under Profile → Settings → GitHub,
  and Packagist installs the hook on the repository.
- No secrets are needed: Packagist reads the public repository.
