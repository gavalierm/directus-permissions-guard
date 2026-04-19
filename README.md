# directus-permissions-guard

Blocking filter hook for Directus 11+ that enforces per-band access rules on `items.create` across content collections. Uses `@directus/errors.ForbiddenError` for clean HTTP 403 responses.

## Rules

| Collection | Required access on target band |
|------------|-------------------------------|
| `songs`, `setlists` | `manager` OR `owner` |
| `albums`, `bands_files` | `owner` only |
| `songs_files`, `songs_authors`, `songs_genres`, `songs_translation_authors` | `manager` OR `owner` of the song's band |
| `setlists_songs`, `setlist_participants`, `setlists_files` | `manager` OR `owner` of the setlist's band |
| `albums_songs` | `owner` of the album's band |

Administrator role bypasses all checks.

## Band resolution

For parent collections (`songs`, `setlists`, `albums`), the target band is read directly from `payload.band`. For junction collections, the hook fetches the parent row to get its `band` FK. For `bands_files`, `payload.bands_id` IS the target band.

## Build

```bash
cd directus/directus-permissions-guard
npm install
npm run build
```

Output: `dist/index.js`.

## Deploy

Drop the folder (or its `dist/`) into the Directus `extensions/` directory on the server, same as the other `directus-*` extensions in this workspace. Restart Directus.

## Why not a Directus Flow

Attempted first — Directus Flow `Run Script` operation runs in an isolated sandbox that cannot import `@directus/errors`, so a `throw` always becomes HTTP 500 with a masked message. Only a proper extension hook (running in host context) can raise `ForbiddenError` and yield a clean 403.
