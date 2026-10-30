# Contributing

Thanks for your interest in arcanum-auth. Questions, bug reports, ideas and
pull requests are welcome.

## Reporting a bug or asking a question

Open an issue: https://github.com/arcanum-pos/arcanum-auth/issues. Say what
you did, what you expected and what happened instead. Issues are public and
stay as an archive.

**Security vulnerabilities: never in a public issue.** See
[SECURITY.md](SECURITY.md) - report them privately through the Security tab.

## Changing the code

1. Open an issue first for anything bigger than a small fix, so we can agree
   on the approach.
2. Keep a change small and focused; follow the style of the code around it
   (TypeScript in strict mode, short functions, a comment where the *why*
   isn't obvious).
3. **Every change ships with tests.** New functionality gets tests that
   cover it; a bug fix gets a test that fails without the fix. Tests live in
   `test/` (Vitest, running in the Cloudflare Workers runtime).
4. Before you open a pull request:
   ```sh
   npm ci
   npm run typecheck   # TypeScript over src and test
   npm test            # the whole suite must pass
   ```
5. Open a pull request against `main` and describe what changed and why.

Every push and pull request runs CI: the tests, TypeScript, `npm audit`,
Semgrep, a ZAP scan of the running pages and CodeQL. A pull request is
merged only when all of them pass.

## License

arcanum-auth is free software under the GNU Affero General Public License
v3.0 (see [LICENSE](LICENSE)). By contributing, you agree that your
contribution is licensed under the same terms.
