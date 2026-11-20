// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { unified } from '@astrojs/markdown-remark';
import starlightGithubAlerts from 'starlight-github-alerts';
import mermaid from 'astro-mermaid';
import { readFileSync } from 'node:fs';
import { sidebarFromManifest } from './scripts/sidebar.mjs';

const manifest = JSON.parse(readFileSync(new URL('./site.manifest.json', import.meta.url), 'utf8'));

// `site` and `base` are overridden in CI with --site/--base from
// actions/configure-pages, so a custom domain later needs no code change.
export default defineConfig({
  site: 'https://rafpe.github.io',
  base: '/pod-certificate-signer',
  trailingSlash: 'always',
  devToolbar: { enabled: false },
  markdown: {
    // Astro 7 defaults to Sätteri; the GitHub-alerts plugin needs remark.
    processor: unified(),
  },
  integrations: [
    mermaid({ theme: 'neutral', autoTheme: true }),
    starlight({
      title: 'pod-certificate-signer',
      description: 'Issue and rotate short-lived certificates for Kubernetes pods.',
      favicon: '/favicon.png',
      logo: { src: '../assets/logo.png', alt: 'pod-certificate-signer' },
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/RafPe/pod-certificate-signer' }],
      editLink: { baseUrl: 'https://github.com/RafPe/pod-certificate-signer/edit/main/' },
      lastUpdated: true,

      customCss: [
        '@fontsource-variable/geist',
        '@fontsource-variable/geist-mono',
        './src/styles/tokens.css',
        './src/styles/starlight.css',
      ],
      components: {
        SiteTitle: './src/components/overrides/SiteTitle.astro',
        // GitHub link plus the documentation version picker.
        SocialIcons: './src/components/overrides/SocialIcons.astro',
      },
      // The docs use promql and logql fences, which Shiki does not ship; render
      // them as plain text instead of warning on every build.
      expressiveCode: { shiki: { langAlias: { promql: 'text', logql: 'text' } } },
      plugins: [starlightGithubAlerts()],
      sidebar: sidebarFromManifest(manifest),
    }),
  ],
});
