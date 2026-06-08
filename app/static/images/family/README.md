# "More from 941 Apps" family strip — portable cross-property kit

A self-contained footer component that cross-links every 941 Apps property
(plus the studio + founder). Built for SEO: real server-rendered `<a>` tags,
not JS or an iframe. Drop it into any of the studio's FastAPI + Jinja sites.

## What's in the kit

- `components/family.html` — the component. Self-contained: its own `<style>`,
  its own Apple-squircle `clipPath`, and root-relative `/static/images/family/`
  asset references. No dependency on the host site's CSS variables, framework,
  fonts, or Jinja globals.
- `static/images/family/*` — the 128px app icons, the square 941 Apps mark
  (`941apps-icon.svg`), and Blake's photo (`blake-crosley.png`).

## Add it to a property

1. Copy `components/family.html` into the site's `templates/components/`.
2. Copy this whole `family/` folder into the site's `static/images/`.
3. Add the include just above (or inside) the footer:
   `{% include "components/family.html" %}`

That's it. The component renders identically on any site that mounts `/static`.

## Theming

Adapts automatically:
- Manual-toggle sites: honors `[data-theme="dark"]` on a parent.
- Auto sites: honors `prefers-color-scheme: dark`.
Titles inherit the host's text color; muted text and borders use neutral grays
that read on any background.

Container width defaults to 1320px (Bootstrap xxl). Override per site:
`.family-strip { --fs-maxw: 1140px; }`

## Maintaining the lineup

The component is hand-authored static HTML (no runtime catalog dependency, so a
site's footer never breaks if another site is down). When the app lineup or a
tagline changes, update this canonical copy and re-copy it to each property.
Generator that produced it: kept with the 941tiles repo history.
