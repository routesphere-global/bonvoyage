# BonVoyage public documentation

This Astro/Starlight site is the separately authored public documentation for
BonVoyage API Gateway. It must not import the private Docusaurus corpus or rely
on files outside the sanitized public repository.

## Local development

```bash
npm ci
npm run dev
```

Build the static site with:

```bash
npm run build
```

The generated site is written to `dist/`.

Dependency lifecycle scripts are disabled by the repository `.npmrc`. The
current exact dependency graph installs and builds without them. Do not bypass
that boundary to repair an install; review and qualify any dependency that
would require lifecycle execution before changing the policy.

## Cloudflare Pages

Use `docs-site` as the project root, `npm run build` as the build command, and
`dist` as the output directory. Pin a Node.js version satisfying the `engines`
field. Connect only the sanitized public repository; never connect the private
founder repository and rely on navigation to hide content.

## Authoring boundary

- Organize content using Diataxis: tutorials teach, how-to guides complete a
  task, reference states exact contracts, and explanation develops the system
  model and design reasoning.
- Write public pages independently from reviewed product behavior.
- Keep internal decisions, founder notes, raw evidence, customer context,
  private vulnerabilities, and commercial planning out of this tree.
- Test every command and workflow against the matching release candidate.
- Use sanitized, release-matched screenshots with useful alternative text.
- Keep limitations and qualification boundaries beside the relevant feature.
