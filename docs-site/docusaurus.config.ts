import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: 'Rikugan',
  tagline: 'The free, open-source DevSecOps vulnerability management platform',
  favicon: 'img/favicon.svg',

  future: {
    v4: true,
  },

  url: 'https://geekshiv.github.io',
  baseUrl: '/rikugan/',

  organizationName: 'geekshiv',
  projectName: 'rikugan',
  deploymentBranch: 'gh-pages',
  trailingSlash: false,

  onBrokenLinks: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          routeBasePath: '/',
          editUrl: 'https://github.com/geekshiv/rikugan/tree/main/docs-site/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    image: 'img/rikugan-social-card.png',
    colorMode: {
      defaultMode: 'dark',
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'Rikugan',
      logo: {
        alt: 'Rikugan',
        src: 'img/brand-mark.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          href: 'https://github.com/geekshiv/rikugan',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {label: 'Getting Started', to: '/getting-started/quickstart'},
            {label: 'GitHub Integration', to: '/github-integration/connecting-github'},
            {label: 'Scanning', to: '/scanning/scanners'},
          ],
        },
        {
          title: 'Community',
          items: [
            {label: 'GitHub Issues', href: 'https://github.com/geekshiv/rikugan/issues'},
            {label: 'Discussions', href: 'https://github.com/geekshiv/rikugan/discussions'},
          ],
        },
        {
          title: 'More',
          items: [
            {label: 'GitHub Repo', href: 'https://github.com/geekshiv/rikugan'},
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Rikugan. 100% free & open-source.`,
    },
    prism: {
      theme: prismThemes.oneLight,
      darkTheme: prismThemes.oneDark,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
