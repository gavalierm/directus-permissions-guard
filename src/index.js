import { ForbiddenError } from '@directus/errors';

// Access level required per collection for items.create:
//   'manager'  → current user must have manager OR owner of target band
//   'owner'    → current user must have owner of target band
//
// Band resolution:
//   bandField       → payload[bandField] IS the target band id (direct FK or bands_id junction)
//   parentLookup    → payload[fk] points to parent; fetch parent row and read parent.band
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
};

async function resolveBandId(payload, rule, database) {
  if (rule.bandField) {
    return payload?.[rule.bandField] ?? null;
  }
  const { collection, fk } = rule.parentLookup;
  const parentId = payload?.[fk];
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

export default ({ filter }, { database, logger }) => {
  for (const [collection, rule] of Object.entries(RULES)) {
    filter(`${collection}.items.create`, async (payload, _meta, { accountability }) => {
      if (accountability?.admin === true) return payload;

      if (!accountability?.user) {
        throw new ForbiddenError();
      }

      const bandId = await resolveBandId(payload, rule, database);
      if (bandId == null) {
        throw new ForbiddenError();
      }

      const allowed = await userHasAccess(accountability.user, bandId, rule.level, database);
      if (!allowed) {
        logger.debug(
          `[permissions-guard] blocked ${collection}.create user=${accountability.user} band=${bandId} required=${rule.level}`
        );
        throw new ForbiddenError();
      }

      return payload;
    });
  }
};
