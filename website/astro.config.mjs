// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { unified } from '@astrojs/markdown-remark';
import starlightGithubAlerts from 'starlight-github-alerts';
import mermaid from 'astro-mermaid';
import { readFileSync } from 'node:fs';
import { sidebarFromManifest } from './scripts/sidebar.mjs';

const manifest = JSON.parse(readFileSync(new URL('./site.manifest.json', import.meta.url), 'utf8'));

export default defineConfig({
  site: 'https://rafpe.github.io',
  base: '/pod-certificate-signer',
  trailingSlash: 'always',
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

      customCss: [
        '@fontsource-variable/source-sans-3',
        '@fontsource/jetbrains-mono/latin-400.css',
        '@fontsource/jetbrains-mono/latin-600.css',
        './src/styles/tokens.css',
        './src/styles/starlight.css',
      ],
      components: {
        SiteTitle: './src/components/overrides/SiteTitle.astro',
      },
      // The docs use promql and logql fences, which Shiki does not ship; render
      // them as plain text instead of warning on every build.
      expressiveCode: { shiki: { langAlias: { promql: 'text', logql: 'text' } } },
      plugins: [starlightGithubAlerts()],
      sidebar: sidebarFromManifest(manifest),
    }),
  ],
});
