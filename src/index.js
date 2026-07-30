import { notifyAdmins } from './shared/notify-admin.js';

// Raising a *clean* 403 needs a Directus-recognized error, which only @directus/errors
// produces. But a STATIC top-level `import { createError } from '@directus/errors'` is not
// reliably resolvable from this extension's runtime: commit 413764c dropped it once for that
// reason, and re-adding it in v1.0.2 broke MODULE LOAD entirely — the default export never
// ran, no filters registered, and every guarded CREATE silently succeeded (worse than a 500).
//
// So resolve it LAZILY (dynamic import, cached, failure caught) with a plain-Error fallback.
// Guarantees: the module always loads and the guard always enforces. Best case a clean 403;
// worst case a still-blocking error (never an unguarded pass-through).
let _forbiddenClass;
let _forbiddenResolved = false;
async function forbidden() {
  if (!_forbiddenResolved) {
    _forbiddenResolved = true;
    try {
      const errors = await import('@directus/errors');
      const createError = errors.createError ?? errors.default?.createError;
      if (typeof createError === 'function') {
        _forbiddenClass = createError(
          'FORBIDDEN',
          'Nemáš oprávnenie vytvárať v tejto kapele (vyžaduje sa manager alebo owner).',
          403,
        );
      }
    } catch {
      // @directus/errors not importable in this runtime — fall back to a plain error below.
    }
  }
  if (_forbiddenClass) return new _forbiddenClass();
  const err = new Error('FORBIDDEN');
  err.status = 403;
  err.code = 'FORBIDDEN';
  err.extensions = { code: 'FORBIDDEN' };
  return err;
}

// Access level required per collection for items.create:
//   'manager'  → current user must have manager OR owner of target band
//   'owner'    → current user must have owner of target band
//
// Band resolution:
//   bandField       → payload[bandField] IS the target band id (direct FK or bands_id junction)
//   parentLookup    → payload[fk] points to parent; fetch parent row and read parent.band
//
// Optional:
//   guardWhen(payload) → when present, only enforce the guard if it returns true; otherwise
//                        pass through to Directus core permissions (e.g. song_notes only
//                        needs a band check for band-visibility notes, not private ones).
const RULES = {
  // Parent collections — band FK on payload
  songs:     { level: 'manager', bandField: 'band' },
  setlists:  { level: 'manager', bandField: 'band' },
  albums:    { level: 'owner',   bandField: 'band' },

  // Junctions with payload.<fk> → parent collection → parent.band
  songs_files:               { level: 'manager', parentLookup: { collection: 'songs',    fk: 'songs_id' } },
  songs_authors:             { level: 'manager', parentLookup: { collection: 'songs',    fk: 'songs_id' } },
  songs_genres:              { level: 'manager', parentLookup: { collection: 'songs',    fk: 'songs_id' } },
  songs_translation_authors: { level: 'manager', parentLookup: { collection: 'songs',    fk: 'songs_id' } },
  setlists_songs:            { level: 'manager', parentLookup: { collection: 'setlists', fk: 'setlists_id' } },
  setlist_participants:      { level: 'manager', parentLookup: { collection: 'setlists', fk: 'setlists_id' } },
  setlists_files:            { level: 'manager', parentLookup: { collection: 'setlists', fk: 'setlists_id' } },
  albums_songs:              { level: 'owner',   parentLookup: { collection: 'albums',   fk: 'albums_id' } },

  // bands_files: bands_id IS the target band
  bands_files:               { level: 'owner',   bandField: 'bands_id' },

  // song_notes: band-visibility notes require manager/owner of the parent song's band.
  // Private notes (visibility !== 'band') are self-scoped — pass through (see guardWhen).
  song_notes:                { level: 'manager', parentLookup: { collection: 'songs',    fk: 'song' }, guardWhen: (p) => p?.visibility === 'band' },
};

// Nested writes through a parent (e.g. PATCH /items/albums/7 with nested M2M create)
// can pass FK fields as reference objects ({ id: 7 }) instead of scalar ids. Knex then
// serializes the object into the bind param and Postgres rejects it with
// "invalid input syntax for type integer". Coerce to scalar before any DB query.
function normalizeId(v) {
  if (v == null) return null;
  if (typeof v === 'object') return v.id ?? null;
  return v;
}

async function resolveBandId(payload, rule, database) {
  if (rule.bandField) {
    return normalizeId(payload?.[rule.bandField]);
  }
  const { collection, fk } = rule.parentLookup;
  const parentId = normalizeId(payload?.[fk]);
  if (parentId == null) return null;
  const parent = await database(collection).where({ id: parentId }).select('band').first();
  return parent?.band ?? null;
}

async function userHasAccess(userId, bandId, level, database) {
  const query = database('access').where({ user: userId, band: bandId });
  if (level === 'owner') {
    query.whereNotNull('owner');
  } else {
    query.andWhere(function () {
      this.whereNotNull('manager').orWhereNotNull('owner');
    });
  }
  const row = await query.select('id').first();
  return !!row;
}

async function guardCreate(collection, payload, accountability, ctx) {
  if (accountability?.admin === true) return payload;

  if (!accountability?.user) {
    throw await forbidden();
  }

  const rule = RULES[collection];

  // Nested create: the band/parent reference can be Directus's "+" placeholder (or otherwise
  // non-numeric) when the referenced row is being created in the SAME request and has no id
  // yet — e.g. a new song created with an author (parentLookup `songs_id`), or a new band
  // created with a file (bandField `bands_id`). We cannot resolve access against a row that
  // does not exist, and feeding "+" into the raw integer lookups below throws at Postgres
  // ("invalid input syntax for type integer") → surfaces to the caller as a 500. Defer to
  // Directus core permissions for these nested rows; where the parent collection has its own
  // create guard it already authorized the band. Real (numeric) references fall through.
  const nestedRef = normalizeId(rule.bandField ? payload?.[rule.bandField] : payload?.[rule.parentLookup.fk]);
  if (nestedRef != null && !/^\d+$/.test(String(nestedRef))) {
    return payload;
  }

  // Conditional rule: only a subset of payloads needs a band check (e.g. a private song_note
  // is self-scoped and requires no manager/owner). Defer the rest to core permissions.
  if (rule.guardWhen && !rule.guardWhen(payload)) {
    return payload;
  }

  const bandId = await resolveBandId(payload, rule, ctx.database);
  if (bandId == null) {
    throw await forbidden();
  }

  const allowed = await userHasAccess(accountability.user, bandId, rule.level, ctx.database);
  if (!allowed) {
    ctx.logger.debug(
      `[permissions-guard] blocked ${collection}.create user=${accountability.user} band=${bandId} required=${rule.level}`
    );
    throw await forbidden();
  }

  return payload;
}

export default ({ filter }, context) => {
  const { services, database, getSchema, logger, env } = context;
  const ctx = { services, database, getSchema, logger, env };

  for (const collection of Object.keys(RULES)) {
    filter(`${collection}.items.create`, async (payload, _meta, { accountability }) => {
      try {
        return await guardCreate(collection, payload, accountability, ctx);
      } catch (err) {
        // Expected: the FORBIDDEN error we raise deliberately (DirectusError or fallback). Silent.
        if (err?.code === 'FORBIDDEN') throw err;

        // Unexpected: DB error, bug, unhandled edge case. Mail admins, then re-throw
        // so Directus still surfaces the error to the caller (do not swallow —
        // the CREATE must fail safe, never let an unverified payload through).
        await notifyAdmins(ctx, `permissions-guard:${collection}`, err, {
          collection,
          user: accountability?.user,
          admin: accountability?.admin === true,
          payloadKeys: payload && typeof payload === 'object' ? Object.keys(payload) : null,
        });
        throw err;
      }
    });
  }
};
