import { defineConfig } from "vitepress";

const raw = process.env.VITEPRESS_BASE?.trim();
const base =
  raw && raw !== "/"
    ? `/${raw.replace(/^\/+|\/+$/g, "")}/`
    : "/";

const userGuide = [
  { text: "Overview", link: "/user/overview" },
  { text: "Quickstart", link: "/user/quickstart" },
  { text: "Services and binaries", link: "/user/services-and-binaries" },
  { text: "Configuration files", link: "/user/configuration-files" },
  { text: "Database", link: "/user/database" },
  { text: "Observability", link: "/user/observability" },
  { text: "Deployment", link: "/user/deployment" },
  { text: "Configuration (reference)", link: "/configuration" },
  { text: "Stability", link: "/stability" },
  { text: "Qualification", link: "/qualification" },
];

const developerGuide = [
  { text: "Workspace layout", link: "/developer/workspace" },
  { text: "Build, test, and CI", link: "/developer/build-and-test" },
  { text: "Architecture", link: "/developer/architecture" },
  { text: "Documentation site", link: "/developer/documentation-site" },
  { text: "Releasing", link: "/RELEASING" },
];

const projectPages = [
  { text: "Changelog", link: "/project/changelog" },
  { text: "License", link: "/project/license" },
];

export default defineConfig({
  title: "Sipora",
  description: "SIP platform: canonical documentation",
  base,
  cleanUrls: true,
  themeConfig: {
    nav: [
      { text: "User guide", link: "/user/overview" },
      { text: "Developer", link: "/developer/workspace" },
      { text: "Reference", link: "/configuration" },
      {
        text: "Project",
        items: [
          { text: "Changelog", link: "/project/changelog" },
          { text: "License", link: "/project/license" },
        ],
      },
    ],
    sidebar: {
      "/": [
        { text: "Home", link: "/" },
        { text: "User guide", items: userGuide },
        { text: "Developer guide", items: developerGuide },
        { text: "Project", items: projectPages },
      ],
      "/user/": [{ text: "User guide", items: userGuide }],
      "/developer/": [{ text: "Developer guide", items: developerGuide }],
      "/project/": [{ text: "Project", items: projectPages }],
    },
    socialLinks: [],
    footer: {
      message: "Apache-2.0",
      copyright: "Sipora contributors",
    },
    search: { provider: "local" },
  },
});
