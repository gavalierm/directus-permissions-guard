const SENSITIVE_KEYS = new Set(['password', 'token', 'access_token', 'refresh_token', 'secret', 'otp']);

function redact(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(redact);
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = SENSITIVE_KEYS.has(k) ? '[REDACTED]' : redact(v);
  }
  return out;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

async function getAdminEmails(database) {
  // Directus 11: admin flag is on policies, assigned either to a role or directly to a user
  // via the directus_access junction table.
  const viaUser = await database('directus_users as u')
    .join('directus_access as da', 'da.user', 'u.id')
    .join('directus_policies as p', 'p.id', 'da.policy')
    .where('p.admin_access', true)
    .where('u.status', 'active')
    .whereNotNull('u.email')
    .select('u.email');

  const viaRole = await database('directus_users as u')
    .join('directus_access as da', 'da.role', 'u.role')
    .join('directus_policies as p', 'p.id', 'da.policy')
    .where('p.admin_access', true)
    .where('u.status', 'active')
    .whereNotNull('u.email')
    .select('u.email');

  return [...new Set([...viaUser, ...viaRole].map((r) => r.email))];
}

export async function notifyAdmins(ctx, source, err, context = {}) {
  const { services, database, getSchema, logger } = ctx;

  const stack = err?.stack || '(no stack)';
  const message = err?.message || String(err);
  logger.error(`[${source}] ${message}\n${stack}`);

  try {
    const adminEmails = await getAdminEmails(database);
    if (!adminEmails.length) {
      logger.warn(`[${source}] no admin emails resolved, notification skipped`);
      return;
    }

    const schema = await getSchema();
    const mailService = new services.MailService({ schema });

    const safeContext = redact(context);
    const contextJson = JSON.stringify(safeContext, null, 2);
    const timestamp = new Date().toISOString();

    const html = `<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',monospace;max-width:720px;padding:16px">
  <h2 style="color:#b91c1c;margin:0 0 12px">Extension error: ${escapeHtml(source)}</h2>
  <p style="margin:4px 0"><strong>Time:</strong> ${escapeHtml(timestamp)}</p>
  <p style="margin:4px 0"><strong>Message:</strong> ${escapeHtml(message)}</p>
  <h3 style="margin:16px 0 4px">Stack trace</h3>
  <pre style="background:#f5f5f5;padding:12px;border-radius:6px;white-space:pre-wrap;font-size:12px;overflow-x:auto;margin:0">${escapeHtml(stack)}</pre>
  <h3 style="margin:16px 0 4px">Context</h3>
  <pre style="background:#f5f5f5;padding:12px;border-radius:6px;white-space:pre-wrap;font-size:12px;overflow-x:auto;margin:0">${escapeHtml(contextJson)}</pre>
</div>`;

    await mailService.send({
      to: adminEmails,
      subject: `[Spevník] Extension error: ${source}`,
      html,
    });
  } catch (notifyErr) {
    logger.error(`[${source}] failed to notify admins: ${notifyErr.message}`);
  }
}
