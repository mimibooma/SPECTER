# Contributing

Bugs, especially from real engagements, are the most useful thing you can
send. Open an issue with what you ran, what you expected, and what happened.
Strip account IDs and anything else you wouldn't paste in public.

Pull requests are welcome. A few things that'll get one merged faster:

- Tests. `python -m unittest discover -s tests` should pass, and new
  detection logic needs a test that would fail without it.
- Keep the read-only guarantee. Nothing in `services/` should call an AWS
  API that mutates state. If you're not sure, it probably does.
- Heuristics should say what they are. Attack patterns and persistence
  checks name things worth verifying, not confirmed compromises. Keep the
  language matching.
- ATT&CK / TTC IDs need to be real. Link to the technique page.

If you want to add a cloud provider, open an issue first so we can agree on
the interface before you write 2,000 lines against the wrong one.
