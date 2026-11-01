# Documentation maintenance

Read the [index](README.md), affected canonical guides and accepted requirements before changing behavior. Keep architectural boundaries, public contracts and operator recovery consistent with source. Update the source-to-guide [map](docs-map.json) when adding a subsystem. Record actual verification separately in [verification](verification.md).

Run `python scripts/check_docs.py` to validate source glob/mapped-file existence and local Markdown file links. It does not validate heading fragments, external URLs, schema semantics, prose accuracy, live integration or deployment. `--impact` prints advisory guide-review suggestions for staged, modified and untracked sources. It does not compare arbitrary historical commits or make unchanged prose an error.

Run `python scripts/check_public_content.py` and `git diff --check` before handoff. The content check is a candidate scanner, not proof that every possible secret format is recognized. Review Git candidates directly and keep all real runtime data outside the checkout. Tests use generated/synthetic fixtures only.
