# Documentation site

The site you are reading is built with [VitePress](https://vitepress.dev/) from Markdown under **`docs/`** in the repository. **This tree is the authoritative product and developer reference**; the root `README.md` only points here so details stay in one place.

## Local preview

Install [Bun](https://bun.sh), then:

```sh
cd docs
bun install
bun run dev
```

## Production build

```sh
cd docs
bun install --frozen-lockfile
bun run build
```

Output is written to **`docs/.vitepress/dist/`**. For GitHub Pages project sites, the build sets `VITEPRESS_BASE` to `/<repository-name>/` so asset URLs resolve.

## Publishing on GitHub Pages

1. Repository **Settings → Pages**: set **Build and deployment** source to **GitHub Actions**.
2. Approve the **`github-pages`** deployment environment when GitHub prompts on first deploy.
3. Workflow **`.github/workflows/docs.yml`** runs on pushes to **`main`** that touch `docs/` or that workflow file, and on **workflow_dispatch**. It installs with Bun, builds with `VITEPRESS_BASE` set from the repository name, uploads the dist directory, and deploys with `actions/deploy-pages`.

The public URL for a default project site is:

`https://coolguy1771.github.io/sipora/`
