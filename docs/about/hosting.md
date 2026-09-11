# Hosting this documentation

The docs are a standard [MkDocs](https://www.mkdocs.org/) site — plain Markdown in `docs/`
built into a static `site/` folder you can host anywhere. Pick whichever option fits.

!!! tip "Set `site_url` first"
    Wherever you host, set `site_url` in `mkdocs.yml` to the final URL (it drives canonical
    links and the sitemap). The default is `https://opslify-com.github.io/opslifyd/`
    (note the `/opslifyd/` base path). Hosting at a domain root? Use e.g.
    `https://docs.example.com/`.

## Option A — GitHub Pages via CI (recommended)

The repo already ships a workflow (`.github/workflows/docs.yml`) that builds and deploys on
every push to `main`, and publishes the one-liner installer at `/install.sh`.

1. In the repo: **Settings → Pages → Build and deployment → Source: `GitHub Actions`**.
2. Ensure Actions is enabled: **Settings → Actions → General → Allow all actions**.
3. Push any docs change (or **Actions → docs → Run workflow**).

Live at `https://<org>.github.io/<repo>/`. Check it:

```bash
gh run watch                                            # follow the build
curl -sI https://<org>.github.io/<repo>/ | head -1      # HTTP 200 = live
```

## Option B — GitHub Pages with one command (`gh-deploy`)

If you'd rather not use the Actions route, build and push to a `gh-pages` branch from a
machine with push access:

```bash
python3 -m venv .venv && .venv/bin/python -m ensurepip -U
.venv/bin/pip install -r docs/requirements.txt
.venv/bin/mkdocs gh-deploy --force
```

Then set **Settings → Pages → Source: Deploy from a branch → `gh-pages` / `root`**.
(Re-run `mkdocs gh-deploy` to update.)

## Option C — any static host / your own server

Build once, then serve the `site/` folder from anything that serves static files.

```bash
python3 -m venv .venv && .venv/bin/python -m ensurepip -U
.venv/bin/pip install -r docs/requirements.txt
.venv/bin/mkdocs build            # outputs ./site/
# publish the one-liner installer too (optional):
cp scripts/get-opslify.sh site/install.sh
```

Then host `site/`:

=== "Netlify / Cloudflare Pages / Vercel"

    Point the project at the repo with:

    - **Build command:** `pip install -r docs/requirements.txt && mkdocs build`
    - **Publish directory:** `site`

    (These platforms give you HTTPS + a domain automatically.)

=== "Nginx"

    ```nginx
    server {
      listen 80;
      server_name docs.example.com;
      root /var/www/opslify-docs/site;   # rsync your built site/ here
      index index.html;
    }
    ```

=== "Caddy (auto-HTTPS)"

    ```
    docs.example.com {
      root * /var/www/opslify-docs/site
      file_server
    }
    ```

=== "S3 + CloudFront"

    ```bash
    aws s3 sync site/ s3://my-docs-bucket/ --delete
    # front with CloudFront for HTTPS + a domain
    ```

=== "Quick local/LAN"

    ```bash
    cd site && python3 -m http.server 8080     # http://<host>:8080
    ```

## Option D — Docker

```dockerfile
# Dockerfile
FROM python:3-slim AS build
WORKDIR /d
COPY . .
RUN pip install -r docs/requirements.txt && mkdocs build && cp scripts/get-opslify.sh site/install.sh

FROM nginx:alpine
COPY --from=build /d/site /usr/share/nginx/html
```

```bash
docker build -t opslify-docs . && docker run -p 8080:80 opslify-docs   # http://localhost:8080
```

## Custom domain

- **GitHub Pages:** add a `CNAME` file (Settings → Pages → Custom domain), and set
  `site_url` to your domain.
- **Other hosts:** point DNS at the host and set `site_url` accordingly.

## Serving the one-liner installer

The install one-liner (`curl -fsSL <site>/install.sh | sudo sh`) works only if
`install.sh` exists at the site root. Option A does this automatically; for B/C/D copy it
yourself:

```bash
cp scripts/get-opslify.sh site/install.sh
```

## Local preview while editing

```bash
.venv/bin/mkdocs serve          # http://127.0.0.1:8000/<base-path>/  (hot-reload)
```

See [Contributing](contributing.md) for the docs workflow.
