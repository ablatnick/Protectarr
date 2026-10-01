# Contributing to Protectarr

Thanks for your interest in improving Protectarr. Bug reports, fixes, new
detection rules, and documentation are all welcome.

## Reporting bugs and ideas

- **Bugs and features:** open a [GitHub issue](https://github.com/ablatnick/Protectarr/issues).
  Include your Protectarr version, how you run it (Docker tag or a build from
  source), and the relevant lines from the container log.
- **Security vulnerabilities:** please **don't** open a public issue. Use
  GitHub's "Report a vulnerability" button (see [SECURITY.md](SECURITY.md)).

## Development setup

Protectarr is a Python package. You need Python 3.11, 3.12, or 3.13.

```bash
git clone https://github.com/ablatnick/Protectarr.git
cd Protectarr
python -m venv .venv && source .venv/bin/activate
pip install -e '.[test]'
```

Run it locally with `protectarr` (it listens on port 9797).

## Running the tests

The unit tests are fast and don't need Docker or any external service:

```bash
pytest -q
```

CI runs this on Python 3.11, 3.12, and 3.13, and builds the Docker image, so
please make sure `pytest -q` passes before opening a pull request.

### End-to-end tests (optional)

`e2e/run.py` spins up a throwaway stack (qBittorrent, Sonarr, Lidarr, Prowlarr,
ClamAV, and Protectarr built from your checkout) and runs real bait scenarios
against it. It needs Docker, and ClamAV takes a few minutes to get ready on the
first run.

```bash
python3 e2e/run.py          # build, start, test, leave the stack up for a look
python3 e2e/run.py --down   # same, then tear the stack down afterwards
```

## Pull requests

- Keep each pull request focused on one change.
- Match the style of the surrounding code; the project has no separate linter
  step beyond the tests.
- Add or update tests for the behavior you change. New detection logic should
  come with a test that shows a bad release being caught and a good one being
  left alone.
- Update the README, `config.example.yml`, and `CHANGELOG.md` when your change
  affects configuration, environment variables, or user-visible behavior.
- Write a clear PR description explaining what changed and why.

## Writing detection rules

Most contributions will touch how a download is judged. The pieces to know:

- `protectarr/rules.py` — name and size heuristics (the fake-release checks).
- `protectarr/filetype.py` — reads a file's real type from its first bytes.
- `protectarr/archives.py` — lists archive contents and flags password-protected ones.
- `protectarr/scanner.py` / `protectarr/clamav.py` — the scan pipeline and the ClamAV client.
- `protectarr/guard.py` — ties the checkpoints together and decides allow / hold / block.

Protectarr is meant to **fail closed**: when something can't be checked (a file
is missing, ClamAV is unreachable, quarantine can't be written), it holds the
download rather than letting it through. Please keep new code consistent with
that principle, and add a test for the failure path as well as the happy path.

## Code of conduct

Be respectful. By participating you agree to keep interactions constructive and
welcoming.

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
