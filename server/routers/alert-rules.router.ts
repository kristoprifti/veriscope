import { Router } from "express";
import { and, eq } from "drizzle-orm";
import { db } from "../db";
import { tenantUsers, users } from "@shared/schema";
import { authenticateApiKey } from "../middleware/apiKeyAuth";
import { requireRole } from "../auth/requireRole";
import { writeAuditEvent } from "../services/auditLog";
import { storage } from "../storage";
import { logger } from "../middleware/observability";

export const alertRulesRouter = Router();

// ---- Private helper: resolve the legacy alertRule userId ----
async function resolveAlertRuleUserId(
  tenantId: string,
  authUserId: string,
): Promise<string | null> {
  const [userRow] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.id, authUserId))
    .limit(1);
  if (userRow) return userRow.id;

  const [tenantRow] = await db
    .select({ email: tenantUsers.email })
    .from(tenantUsers)
    .where(and(eq(tenantUsers.tenantId, tenantId), eq(tenantUsers.userId, authUserId)))
    .limit(1);

  const email = tenantRow?.email ?? `api+${authUserId.slice(0, 6)}@veriscope.dev`;
  const [emailRow] = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1);
  if (emailRow) return emailRow.id;

  if (process.env.NODE_ENV === "production") return null;

  try {
    await db
      .insert(users)
      .values({ id: authUserId, email, passwordHash: "api_key_only", role: "analyst", isActive: true })
      .onConflictDoNothing();
  } catch {
    // ignore
  }

  const [created] = await db.select({ id: users.id }).from(users).where(eq(users.id, authUserId)).limit(1);
  if (created) return created.id;

  const [afterEmail] = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1);
  return afterEmail?.id ?? null;
}

const mapRule = (rule: any) => ({
  id: rule.id,
  name: rule.name,
  type: rule.type,
  is_active: rule.isActive ?? true,
  is_muted: rule.isMuted ?? false,
  severity: rule.severity ?? "medium",
  conditions: rule.conditions ?? {},
  channels: rule.channels ?? [],
  cooldown_minutes: rule.cooldownMinutes ?? 60,
  watchlist_id: rule.watchlistId ?? null,
  snoozed_until: rule.snoozedUntil ?? null,
  last_triggered_at: rule.lastTriggered ?? null,
  trigger_count: rule.triggerCount ?? 0,
  created_at: rule.createdAt,
});

// GET /v1/alert-rules
alertRulesRouter.get("/v1/alert-rules", authenticateApiKey, async (req, res, next) => {
  try {
    requireRole(req.auth, "VIEWER");
  } catch (err: any) {
    await writeAuditEvent(req.auditContext, {
      action: "AUTH.RBAC_DENIED",
      resourceType: "RBAC",
      status: "DENIED",
      severity: "SECURITY",
      message: "Role is not permitted for this operation.",
      metadata: { path: req.path, role: req.auth?.role, required: "VIEWER" },
    }).catch(() => {});
    return res.status(err.status ?? 403).json({ error: err.status === 401 ? "UNAUTHORIZED" : "FORBIDDEN", detail: err.message });
  }
  try {
    const tenantId = req.auth?.tenantId;
    const authUserId = req.auth?.userId;
    if (!tenantId || !authUserId) return res.status(401).json({ error: "API key required" });

    const userId = await resolveAlertRuleUserId(tenantId, authUserId);
    if (!userId) return res.status(403).json({ error: "FORBIDDEN", detail: "Alert rules user missing" });

    const rules = await storage.getAlertRules(userId);
    res.json({ version: "1", items: rules.map(mapRule) });
  } catch (err) {
    logger.error("Failed to fetch alert rules", { err });
    next(err);
  }
});

// POST /v1/alert-rules
alertRulesRouter.post("/v1/alert-rules", authenticateApiKey, async (req, res, next) => {
  try {
    requireRole(req.auth, "OPERATOR");
  } catch (err: any) {
    await writeAuditEvent(req.auditContext, {
      action: "AUTH.RBAC_DENIED",
      resourceType: "RBAC",
      status: "DENIED",
      severity: "SECURITY",
      message: "Role is not permitted for this operation.",
      metadata: { path: req.path, role: req.auth?.role, required: "OPERATOR" },
    }).catch(() => {});
    return res.status(err.status ?? 403).json({ error: err.status === 401 ? "UNAUTHORIZED" : "FORBIDDEN", detail: err.message });
  }
  try {
    const tenantId = req.auth?.tenantId;
    const authUserId = req.auth?.userId;
    if (!tenantId || !authUserId) return res.status(401).json({ error: "API key required" });

    const userId = await resolveAlertRuleUserId(tenantId, authUserId);
    if (!userId) return res.status(403).json({ error: "FORBIDDEN", detail: "Alert rules user missing" });

    const name = String(req.body?.name ?? "").trim();
    const type = String(req.body?.type ?? "").trim();
    if (!name || !type) return res.status(400).json({ error: "name and type are required" });

    const conditions = req.body?.conditions ?? {};
    const channels = Array.isArray(req.body?.channels) ? req.body.channels : ["in_app"];
    const cooldownMinutes = Number(req.body?.cooldown_minutes ?? req.body?.cooldownMinutes ?? 60);
    const severity = String(req.body?.severity ?? "medium");
    const isActive = req.body?.is_active !== false && req.body?.isActive !== false;
    const isMuted = req.body?.is_muted === true || req.body?.isMuted === true;

    const rule = await storage.createAlertRule({
      userId,
      name,
      type,
      conditions,
      channels,
      cooldownMinutes: Number.isFinite(cooldownMinutes) ? cooldownMinutes : 60,
      watchlistId: req.body?.watchlist_id ?? req.body?.watchlistId ?? undefined,
      isActive,
      severity,
      isMuted,
    });

    res.status(201).json({ version: "1", item: mapRule(rule) });
  } catch (err) {
    logger.error("Failed to create alert rule", { err });
    next(err);
  }
});

// PATCH /v1/alert-rules/:id
alertRulesRouter.patch("/v1/alert-rules/:id", authenticateApiKey, async (req, res, next) => {
  try {
    requireRole(req.auth, "OPERATOR");
  } catch (err: any) {
    await writeAuditEvent(req.auditContext, {
      action: "AUTH.RBAC_DENIED",
      resourceType: "RBAC",
      status: "DENIED",
      severity: "SECURITY",
      message: "Role is not permitted for this operation.",
      metadata: { path: req.path, role: req.auth?.role, required: "OPERATOR" },
    }).catch(() => {});
    return res.status(err.status ?? 403).json({ error: err.status === 401 ? "UNAUTHORIZED" : "FORBIDDEN", detail: err.message });
  }
  try {
    const tenantId = req.auth?.tenantId;
    const authUserId = req.auth?.userId;
    if (!tenantId || !authUserId) return res.status(401).json({ error: "API key required" });

    const userId = await resolveAlertRuleUserId(tenantId, authUserId);
    if (!userId) return res.status(403).json({ error: "FORBIDDEN", detail: "Alert rules user missing" });

    const id = String(req.params.id ?? "");
    if (!id) return res.status(400).json({ error: "rule id required" });

    const existing = await storage.getAlertRuleById(id);
    if (!existing) return res.status(404).json({ error: "alert rule not found" });
    if (existing.userId !== userId) return res.status(403).json({ error: "FORBIDDEN", detail: "Rule does not belong to user" });

    const updates: Record<string, unknown> = {};
    if (req.body?.name !== undefined) updates.name = String(req.body.name).trim();
    if (req.body?.type !== undefined) updates.type = String(req.body.type).trim();
    if (req.body?.conditions !== undefined) updates.conditions = req.body.conditions ?? {};
    if (req.body?.channels !== undefined) updates.channels = Array.isArray(req.body.channels) ? req.body.channels : ["in_app"];
    if (req.body?.cooldown_minutes !== undefined || req.body?.cooldownMinutes !== undefined) {
      const raw = Number(req.body?.cooldown_minutes ?? req.body?.cooldownMinutes);
      if (Number.isFinite(raw)) updates.cooldownMinutes = raw;
    }
    if (req.body?.severity !== undefined) updates.severity = String(req.body.severity);
    if (req.body?.is_active !== undefined || req.body?.isActive !== undefined) {
      updates.isActive = req.body?.is_active !== false && req.body?.isActive !== false;
    }
    if (req.body?.is_muted !== undefined || req.body?.isMuted !== undefined) {
      updates.isMuted = req.body?.is_muted === true || req.body?.isMuted === true;
    }

    const rule = await storage.updateAlertRule(id, updates as any);
    res.json({ version: "1", item: mapRule(rule) });
  } catch (err) {
    logger.error("Failed to update alert rule", { err });
    next(err);
  }
});

// DELETE /v1/alert-rules/:id
alertRulesRouter.delete("/v1/alert-rules/:id", authenticateApiKey, async (req, res, next) => {
  try {
    requireRole(req.auth, "OPERATOR");
  } catch (err: any) {
    await writeAuditEvent(req.auditContext, {
      action: "AUTH.RBAC_DENIED",
      resourceType: "RBAC",
      status: "DENIED",
      severity: "SECURITY",
      message: "Role is not permitted for this operation.",
      metadata: { path: req.path, role: req.auth?.role, required: "OPERATOR" },
    }).catch(() => {});
    return res.status(err.status ?? 403).json({ error: err.status === 401 ? "UNAUTHORIZED" : "FORBIDDEN", detail: err.message });
  }
  try {
    const tenantId = req.auth?.tenantId;
    const authUserId = req.auth?.userId;
    if (!tenantId || !authUserId) return res.status(401).json({ error: "API key required" });

    const userId = await resolveAlertRuleUserId(tenantId, authUserId);
    if (!userId) return res.status(403).json({ error: "FORBIDDEN", detail: "Alert rules user missing" });

    const id = String(req.params.id ?? "");
    if (!id) return res.status(400).json({ error: "rule id required" });

    const existing = await storage.getAlertRuleById(id);
    if (!existing) return res.status(404).json({ error: "alert rule not found" });
    if (existing.userId !== userId) return res.status(403).json({ error: "FORBIDDEN", detail: "Rule does not belong to user" });

    await storage.deleteAlertRule(id);
    res.json({ version: "1", deleted: true });
  } catch (err) {
    logger.error("Failed to delete alert rule", { err });
    next(err);
  }
});
