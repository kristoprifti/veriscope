import { Router } from "express";
import { and, eq, inArray, or } from "drizzle-orm";
import { db } from "../db";
import {
  alertDlq,
  alertEndpointHealth,
  alertSubscriptions,
  ports,
  signals,
} from "@shared/schema";
import { authenticateApiKey } from "../middleware/apiKeyAuth";
import { requireRole } from "../auth/requireRole";
import { writeAuditEvent } from "../services/auditLog";
import {
  canTransitionDestinationState,
  bulkUpdateDestinationStates,
  getDestinationDetail,
  listDestinations,
  upsertDestinationState,
} from "../services/alertDestinationStateService";
import {
  getDestinationOverrides,
  resolveNoiseBudget,
  resolveSlaThresholds,
  upsertDestinationOverrides,
} from "../services/alertDestinationOverridesService";
import { listEndpointHealth } from "../services/alertEndpointHealthService";
import { listAlertDeliveries } from "../services/alertDeliveries";
import { listAuditEvents } from "../services/auditEvents";
import { buildSignalClusterAlertPayload } from "../services/signalAlertService";
import { formatSignalDay } from "../services/signalEngineService";
import { SEVERITY_RANK, type SignalSeverity, type ConfidenceBand } from "@shared/signalTypes";
import { logger } from "../middleware/observability";

export const destinationsRouter = Router();

type SignalEntity = { id: string; type: "port"; name: string; code: string | null; unlocode: string | null };

async function guardRole(req: any, res: any, minRole: "OWNER" | "OPERATOR" | "VIEWER"): Promise<boolean> {
  try {
    requireRole(req.auth, minRole);
    return true;
  } catch (err: any) {
    await writeAuditEvent(req.auditContext, {
      action: "AUTH.RBAC_DENIED",
      resourceType: "RBAC",
      status: "DENIED",
      severity: "SECURITY",
      message: "Role is not permitted for this operation.",
      metadata: { path: req.path, method: req.method, role: req.auth?.role, required: minRole },
    }).catch(() => {});
    const status = err?.status ?? 403;
    res.status(status).json({ error: status === 401 ? "UNAUTHORIZED" : "FORBIDDEN", detail: err?.message ?? "Forbidden" });
    return false;
  }
}

// ---- mapAlertDeliveryRows: enriches raw delivery rows with signals, DLQ, and endpoint health ----
async function mapAlertDeliveryRows(args: {
  items: any[];
  tenantId: string;
  includeEntity: boolean;
}) {
  const { items, tenantId, includeEntity } = args;
  if (!items.length) return [];

  const deliverySubscriptionIds = Array.from(new Set(items.map((row) => row.subscriptionId)));
  const subscriptionRows = deliverySubscriptionIds.length > 0
    ? await db
        .select({ id: alertSubscriptions.id, scope: alertSubscriptions.scope, entityId: alertSubscriptions.entityId, entityType: alertSubscriptions.entityType })
        .from(alertSubscriptions)
        .where(and(inArray(alertSubscriptions.id, deliverySubscriptionIds), eq(alertSubscriptions.tenantId, tenantId)))
    : [];
  const subscriptionMap = new Map(subscriptionRows.map((row) => [row.id, row]));

  const deliveryIds = items.map((row) => row.id);
  const dlqRows = deliveryIds.length > 0
    ? await db
        .select({ deliveryId: alertDlq.deliveryId, attemptCount: alertDlq.attemptCount, maxAttempts: alertDlq.maxAttempts, nextAttemptAt: alertDlq.nextAttemptAt })
        .from(alertDlq)
        .where(and(inArray(alertDlq.deliveryId, deliveryIds), eq(alertDlq.tenantId, tenantId)))
    : [];
  const dlqMap = new Map(dlqRows.map((row) => [row.deliveryId, row]));

  const clusterIds = Array.from(new Set(items.map((row) => row.clusterId).filter(Boolean))) as string[];
  const signalRows = clusterIds.length > 0
    ? await db
        .select({
          id: signals.id,
          clusterId: signals.clusterId,
          clusterSeverity: signals.clusterSeverity,
          clusterSummary: signals.clusterSummary,
          confidenceScore: signals.confidenceScore,
          confidenceBand: signals.confidenceBand,
          method: signals.method,
          entityId: signals.entityId,
          day: signals.day,
          metadata: signals.metadata,
          createdAt: signals.createdAt,
        })
        .from(signals)
        .where(inArray(signals.clusterId, clusterIds))
    : [];

  const signalMap = new Map<string, (typeof signalRows)[number]>();
  for (const row of signalRows) {
    const dayValue = (row.day as unknown) instanceof Date ? formatSignalDay(row.day as unknown as Date) : String(row.day);
    const key = `${row.clusterId}|${row.entityId}|${dayValue}`;
    const existing = signalMap.get(key);
    if (!existing) { signalMap.set(key, row); continue; }
    const rank = (r: typeof row) => ({ rank: SEVERITY_RANK[String(r.clusterSeverity ?? "LOW").toUpperCase() as keyof typeof SEVERITY_RANK] ?? 0, confidence: Number(r.confidenceScore ?? 0) });
    const curr = rank(existing);
    const next = rank(row);
    if (next.rank > curr.rank || (next.rank === curr.rank && next.confidence > curr.confidence)) {
      signalMap.set(key, row);
    }
  }

  let entityMap: Map<string, SignalEntity> | null = null;
  if (includeEntity) {
    const portIds = Array.from(new Set(items.map((row) => row.entityId))).filter((v): v is string => Boolean(v));
    if (portIds.length > 0) {
      const portRows = await db
        .select({ id: ports.id, name: ports.name, code: ports.code, unlocode: ports.unlocode })
        .from(ports)
        .where(inArray(ports.id, portIds));
      entityMap = new Map(portRows.map((row) => [row.id, { id: row.id, type: "port", name: row.name, code: row.code, unlocode: row.unlocode ?? null }]));
    } else {
      entityMap = new Map();
    }
  }

  const endpointPairs = Array.from(new Set(items.map((row) => `${row.destinationType}|||${row.endpoint}`)));
  const endpointHealthRows = endpointPairs.length > 0
    ? await db
        .select({
          destinationType: alertEndpointHealth.destinationType,
          destination: alertEndpointHealth.destination,
          status: alertEndpointHealth.status,
          successRate: alertEndpointHealth.successRate,
          p95Ms: alertEndpointHealth.p95Ms,
          lastSuccessAt: alertEndpointHealth.lastSuccessAt,
          lastFailureAt: alertEndpointHealth.lastFailureAt,
          updatedAt: alertEndpointHealth.updatedAt,
        })
        .from(alertEndpointHealth)
        .where(
          and(
            eq(alertEndpointHealth.tenantId, tenantId),
            eq(alertEndpointHealth.window, "1h"),
            or(
              ...endpointPairs.map((pair) => {
                const [dtype, dest] = pair.split("|||");
                return and(eq(alertEndpointHealth.destinationType, dtype), eq(alertEndpointHealth.destination, dest));
              }),
            ),
          ),
        )
    : [];
  const endpointHealthMap = new Map(endpointHealthRows.map((row) => [`${row.destinationType}|||${row.destination}`, row]));

  return items.map((row) => {
    const dayValue = (row.day as unknown) instanceof Date ? formatSignalDay(row.day as Date) : String(row.day);
    const key = `${row.clusterId}|${row.entityId}|${dayValue}`;
    const signalRow = signalMap.get(key);
    const sub = subscriptionMap.get(row.subscriptionId);
    const dlq = dlqMap.get(row.id);
    const eh = endpointHealthMap.get(`${row.destinationType}|||${row.endpoint}`);

    const bundlePayload = (row as any).bundlePayload ?? null;
    const alertPayload = bundlePayload ?? (signalRow
      ? buildSignalClusterAlertPayload({
          day: signalRow.day,
          entityType: "port",
          entityId: signalRow.entityId,
          clusterId: signalRow.clusterId,
          clusterSeverity: signalRow.clusterSeverity as SignalSeverity | null,
          confidenceScore: signalRow.confidenceScore,
          confidenceBand: signalRow.confidenceBand as ConfidenceBand | null,
          clusterSummary: signalRow.clusterSummary,
          metadata: signalRow.metadata ?? {},
        })
      : null);

    return {
      id: row.id,
      subscription_id: row.subscriptionId,
      scope: sub?.scope ?? "PORT",
      entity_id: row.entityId,
      entity_type: sub?.entityType ?? "port",
      entity: includeEntity ? (entityMap?.get(row.entityId) ?? null) : undefined,
      cluster_id: row.clusterId,
      cluster_day: dayValue,
      destination_type: row.destinationType,
      destination: row.endpoint,
      status: row.status,
      attempt_count: row.attemptCount ?? 0,
      last_attempt_at: row.lastAttemptAt ?? null,
      next_attempt_at: dlq?.nextAttemptAt ?? null,
      dlq: dlq ? { attempt_count: dlq.attemptCount, max_attempts: dlq.maxAttempts, next_attempt_at: dlq.nextAttemptAt } : null,
      endpoint_health: eh ? { status: eh.status, success_rate: eh.successRate, p95_ms: eh.p95Ms, last_success_at: eh.lastSuccessAt, last_failure_at: eh.lastFailureAt } : null,
      payload: alertPayload,
      created_at: row.createdAt,
    };
  });
}

// GET /v1/alert-destinations
destinationsRouter.get("/v1/alert-destinations", authenticateApiKey, async (req, res, next) => {
  if (!(await guardRole(req, res, "VIEWER"))) return;
  try {
    const tenantId = req.auth?.tenantId;
    if (!tenantId) return res.status(401).json({ error: "API key required" });

    const window = String(req.query?.window ?? "24h");
    if (window !== "1h" && window !== "24h") return res.status(400).json({ error: "window must be 1h or 24h" });

    const state = req.query?.state ? String(req.query.state).toUpperCase() : undefined;
    if (state && !["ACTIVE", "PAUSED", "AUTO_PAUSED", "DISABLED"].includes(state)) {
      return res.status(400).json({ error: "state must be ACTIVE, PAUSED, AUTO_PAUSED, or DISABLED" });
    }

    const destinationType = req.query?.destination_type ? String(req.query.destination_type).toUpperCase() : undefined;
    if (destinationType && !["WEBHOOK", "EMAIL"].includes(destinationType)) {
      return res.status(400).json({ error: "destination_type must be WEBHOOK or EMAIL" });
    }

    const q = req.query?.q ? String(req.query.q) : undefined;
    const limitRaw = Number(req.query?.limit ?? 50);
    const limit = Number.isFinite(limitRaw) ? limitRaw : 50;
    const cursor = req.query?.cursor ? String(req.query.cursor) : undefined;
    const includeOverrides = String(req.query?.include_overrides ?? "") === "true";

    const result = await listDestinations({ tenantId, window: window as "1h" | "24h", state, destinationType, q, limit, cursor, includeOverrides });
    res.json(result);
  } catch (err) {
    logger.error("Failed to fetch destination states", { err });
    next(err);
  }
});

// GET /v1/alert-destinations/:destination_key
destinationsRouter.get("/v1/alert-destinations/:destination_key", authenticateApiKey, async (req, res, next) => {
  if (!(await guardRole(req, res, "VIEWER"))) return;
  try {
    const tenantId = req.auth?.tenantId;
    const userId = req.auth?.userId;
    if (!tenantId || !userId) return res.status(401).json({ error: "API key required" });

    const destinationKey = String(req.params.destination_key ?? "");
    if (!destinationKey) return res.status(400).json({ error: "destination_key required" });

    const detail = await getDestinationDetail({ tenantId, destinationKey, windows: { endpointHealth: "1h", sla: "24h" } });
    if (!detail) return res.status(404).json({ error: "DESTINATION_NOT_FOUND" });

    const deliveryLimit = 20;
    const { items } = await listAlertDeliveries({ tenantId, userId, destinationKey, limit: deliveryLimit });
    const mappedDeliveries = await mapAlertDeliveryRows({ items, tenantId, includeEntity: false });
    const last = items.length > 0 ? items[items.length - 1] : null;
    const nextCursor = items.length === deliveryLimit && last?.createdAt
      ? Buffer.from(`${new Date(last.createdAt as any).toISOString()}|${last.id}`).toString("base64")
      : null;

    const auditLimitRaw = Number(req.query?.audit_limit ?? 20);
    const auditLimit = Number.isFinite(auditLimitRaw) ? Math.min(Math.max(auditLimitRaw, 1), 50) : 20;
    const auditRows = await listAuditEvents({ tenantId, resourceType: "ALERT_DESTINATION", resourceId: destinationKey, limit: auditLimit });
    const auditItems = auditRows.items.map((row) => ({
      id: row.id, tenant_id: row.tenantId, actor_type: row.actorType, actor_user_id: row.actorUserId ?? null,
      actor_api_key_id: row.actorApiKeyId ?? null, actor_label: row.actorLabel ?? null,
      action: row.action, resource_type: row.resourceType, resource_id: row.resourceId ?? null,
      severity: row.severity, status: row.status, message: row.message, metadata: row.metadata ?? {},
      ip: row.ip ?? null, user_agent: row.userAgent ?? null, request_id: row.requestId ?? null, created_at: row.createdAt,
    }));
    const lastAudit = auditRows.items.length > 0 ? auditRows.items[auditRows.items.length - 1] : null;
    const auditNextCursor = auditRows.items.length === auditLimit && lastAudit?.createdAt
      ? Buffer.from(`${new Date(lastAudit.createdAt as any).toISOString()}|${lastAudit.id}`).toString("base64")
      : null;

    res.json({ version: "1", ...detail, recent_deliveries: { items: mappedDeliveries, next_cursor: nextCursor }, audit_preview: { items: auditItems, next_cursor: auditNextCursor } });
  } catch (err) {
    logger.error("Failed to fetch destination detail", { err });
    next(err);
  }
});

// PATCH /v1/alert-destinations/:destination_key/state — specific param before generic state
destinationsRouter.patch("/v1/alert-destinations/:destination_key/state", authenticateApiKey, async (req, res, next) => {
  try {
    const tenantId = req.auth?.tenantId;
    const userId = req.auth?.userId;
    if (!tenantId) return res.status(401).json({ error: "API key required" });
    const role = req.auth?.role ?? "VIEWER";

    const destinationKey = String(req.params.destination_key ?? "");
    if (!destinationKey) return res.status(400).json({ error: "destination_key required" });

    const state = String(req.body?.state ?? "").toUpperCase();
    if (!["ACTIVE", "PAUSED", "DISABLED"].includes(state)) {
      return res.status(400).json({ error: "state must be ACTIVE, PAUSED, or DISABLED" });
    }
    if (!canTransitionDestinationState(role, state as any)) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const lookup = await listDestinations({ tenantId, limit: 10000, window: "24h" });
    const target = lookup.items.find((item: any) => item.destination_key === destinationKey);
    if (!target) return res.status(404).json({ error: "Destination not found" });

    const result = await upsertDestinationState({ tenantId, userId, destinationType: target.destination_type, destinationKey, state: state as any, reason: req.body?.note ?? null });

    await writeAuditEvent(req.auditContext, {
      action: "ALERT.DESTINATION_STATE_CHANGED",
      resourceType: "ALERT_DESTINATION",
      resourceId: destinationKey,
      status: "SUCCESS",
      severity: "SECURITY",
      message: `Destination state set to ${state}`,
      metadata: { destination_type: target.destination_type, destination_key: destinationKey, state, note: req.body?.note ?? null },
    });

    res.json({ version: "1", item: result });
  } catch (err) {
    logger.error("Failed to update destination state", { err });
    next(err);
  }
});

// GET /v1/alert-destination-overrides/:destination_key
destinationsRouter.get("/v1/alert-destination-overrides/:destination_key", authenticateApiKey, async (req, res, next) => {
  if (!(await guardRole(req, res, "VIEWER"))) return;
  try {
    const tenantId = req.auth?.tenantId;
    if (!tenantId) return res.status(401).json({ error: "API key required" });

    const destinationKey = String(req.params.destination_key ?? "");
    if (!destinationKey) return res.status(400).json({ error: "destination_key required" });

    const lookup = await listDestinations({ tenantId, limit: 10000, window: "24h" });
    const target = lookup.items.find((item: any) => item.destination_key === destinationKey);
    if (!target) return res.status(404).json({ error: "Destination not found" });

    const overrides = await getDestinationOverrides(tenantId, destinationKey);
    const [resolvedNoise, resolvedSla24, resolvedSla7] = await Promise.all([
      resolveNoiseBudget({ tenantId, destinationType: String(target.destination_type).toUpperCase() as any, destinationKey, destination: target.destination ?? null, now: new Date() }),
      resolveSlaThresholds({ tenantId, window: "24h", destinationType: String(target.destination_type).toUpperCase() as any, destinationKey }),
      resolveSlaThresholds({ tenantId, window: "7d", destinationType: String(target.destination_type).toUpperCase() as any, destinationKey }),
    ]);

    res.json({
      version: "1",
      destination_key: destinationKey,
      destination_type: target.destination_type,
      destination: target.destination ?? null,
      overrides: overrides?.row ?? null,
      sla_overrides: overrides?.sla_overrides ?? [],
      resolved: { noise_budget: resolvedNoise, sla: { "24h": resolvedSla24, "7d": resolvedSla7 } },
    });
  } catch (err) {
    logger.error("Failed to fetch destination overrides", { err });
    next(err);
  }
});

// PATCH /v1/alert-destination-overrides/:destination_key
destinationsRouter.patch("/v1/alert-destination-overrides/:destination_key", authenticateApiKey, async (req, res, next) => {
  if (!(await guardRole(req, res, "OWNER"))) return;
  try {
    const tenantId = req.auth?.tenantId;
    if (!tenantId) return res.status(401).json({ error: "API key required" });

    const destinationKey = String(req.params.destination_key ?? "");
    if (!destinationKey) return res.status(400).json({ error: "destination_key required" });

    const lookup = await listDestinations({ tenantId, limit: 10000, window: "24h" });
    const target = lookup.items.find((item: any) => item.destination_key === destinationKey);
    if (!target) return res.status(404).json({ error: "Destination not found" });

    const payload = req.body ?? {};
    const noiseBudget = payload.noise_budget ?? payload.noiseBudget ?? null;
    const sla = payload.sla ?? null;

    const updated = await upsertDestinationOverrides({
      tenantId, destinationKey,
      destinationType: String(target.destination_type).toUpperCase() as any,
      noiseBudget: noiseBudget ?? null,
      sla: sla ?? null,
      updatedByUserId: req.auth?.userId ?? null,
      updatedByKeyId: req.auth?.apiKeyId ?? null,
    });

    await writeAuditEvent(req.auditContext, {
      action: "ALERT.DESTINATION_OVERRIDES_UPDATED",
      resourceType: "ALERT_DESTINATION",
      resourceId: destinationKey,
      status: "SUCCESS",
      severity: "SECURITY",
      message: "Destination overrides updated",
      metadata: { destination_type: target.destination_type, destination_key: destinationKey, noise_budget: noiseBudget ?? null, sla: sla ?? null },
    });

    res.json({ version: "1", item: updated });
  } catch (err: any) {
    res.status(400).json({ error: "Failed to update destination overrides" });
  }
});

// POST /v1/alert-destinations/bulk/state
destinationsRouter.post("/v1/alert-destinations/bulk/state", authenticateApiKey, async (req, res, next) => {
  try {
    const tenantId = req.auth?.tenantId;
    const userId = req.auth?.userId;
    if (!tenantId) return res.status(401).json({ error: "API key required" });
    const role = req.auth?.role ?? "VIEWER";

    const keys = Array.isArray(req.body?.destination_keys) ? req.body.destination_keys.map(String) : [];
    if (keys.length === 0) return res.status(400).json({ error: "destination_keys required" });

    const state = String(req.body?.state ?? "").toUpperCase();
    if (!["ACTIVE", "PAUSED", "DISABLED"].includes(state)) {
      return res.status(400).json({ error: "state must be ACTIVE, PAUSED, or DISABLED" });
    }
    if (!canTransitionDestinationState(role, state as any)) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const bulkResult = await bulkUpdateDestinationStates({ tenantId, userId, destinationKeys: keys, state: state as any, reason: req.body?.note ?? null });

    for (const item of bulkResult.results) {
      if (item.status !== "ok") continue;
      await writeAuditEvent(req.auditContext, {
        action: "ALERT.DESTINATION_STATE_CHANGED",
        resourceType: "ALERT_DESTINATION",
        resourceId: item.destination_key,
        status: "SUCCESS",
        severity: "SECURITY",
        message: `Destination state set to ${state}`,
        metadata: { destination_key: item.destination_key, state, note: req.body?.note ?? null },
      }).catch(() => {});
    }

    res.json(bulkResult);
  } catch (err) {
    logger.error("Failed to bulk update destination states", { err });
    next(err);
  }
});
