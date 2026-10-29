// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://docs.routesphere.global',
  output: 'static',
  integrations: [
    starlight({
      title: 'RouteSphere BonVoyage API Gateway',
      description: 'Install, configure, operate, and verify the BonVoyage API gateway.',
      favicon: '/favicon.svg',
      logo: {
        src: './src/assets/routesphere-mark.svg',
        alt: '',
      },
      customCss: ['./src/styles/custom.css'],
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'Documentation home', slug: 'index' },
            { label: 'Requirements', slug: 'getting-started/requirements' },
          ],
        },
        {
          label: 'Tutorials',
          items: [
            { label: 'Docker quickstart', slug: 'getting-started/quickstart' },
          ],
        },
        {
          label: 'How-to guides',
          items: [
            { label: 'Verify a local deployment', slug: 'how-to/verify-local-deployment' },
            { label: 'Verify a Kubernetes deployment', slug: 'how-to/verify-kubernetes-deployment' },
            { label: 'Reproduce the bounded benchmark', slug: 'how-to/reproduce-bounded-benchmark' },
            { label: 'Validate a configuration', slug: 'how-to/validate-configuration' },
            { label: 'Format a configuration', slug: 'how-to/format-configuration' },
            { label: 'Explain a configuration field', slug: 'how-to/explain-configuration-field' },
            { label: 'Compare configurations', slug: 'how-to/compare-configurations' },
            { label: 'Migrate a configuration', slug: 'how-to/migrate-configuration' },
            { label: 'Preview a configuration', slug: 'how-to/preview-configuration' },
          ],
        },
        {
          label: 'Console Free',
          items: [
            { label: 'Console overview', slug: 'console' },
            { label: 'Create the first administrator', slug: 'console/create-first-administrator' },
            { label: 'Sign in and inspect', slug: 'console/sign-in-and-inspect' },
            { label: 'Apply a configuration', slug: 'console/apply-configuration' },
            { label: 'Recover a rejected rollout', slug: 'console/recover-rejected-rollout' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'YAML parameter reference', slug: 'reference/configuration-parameters' },
            { label: 'Configuration authoring contract', slug: 'reference/configuration-authoring-contract' },
            { label: 'Configuration completion metadata', slug: 'reference/configuration-completion-metadata' },
            { label: 'Configuration snippets', slug: 'reference/configuration-snippets' },
            { label: 'Configuration diagnostics', slug: 'reference/configuration-diagnostics' },
            { label: 'Configuration test corpus', slug: 'reference/configuration-test-corpus' },
            { label: 'Assistant skill contract', slug: 'reference/assistant-skill-contract' },
            { label: 'Assistant skill evaluations', slug: 'reference/assistant-skill-evaluations' },
            { label: 'ChatGPT and Codex skill', slug: 'reference/openai-codex-configuration-skill' },
            { label: 'Claude Code skill', slug: 'reference/claude-configuration-skill' },
            { label: 'Supported capabilities', slug: 'reference/supported-capabilities' },
            { label: 'Support and security', slug: 'reference/support-and-security' },
          ],
        },
        {
          label: 'Explanation',
          items: [
            { label: 'System model', slug: 'concepts/system-model' },
            { label: 'Configuration lifecycle', slug: 'concepts/configuration-lifecycle' },
          ],
        },
      ],
    }),
  ],
});
