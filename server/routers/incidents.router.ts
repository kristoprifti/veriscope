import { Router } from "express";
import { and, eq } from "drizzle-orm";
import { db } from "../db";
import { incidents } from "@shared/schema";
import { authenticateApiKey } from "../middleware/apiKeyAuth";
import { requireRole } from "../auth/requireRole";
import { writeAuditEvent } from "../services/auditLog";
import { logOpsEvent } from "../services/opsTelemetry";
import { listIncidents, getIncidentsSummary, getIncidentById } from "../services/incidentService";
import { getIncidentMetricsV1 } from "../services/incidentMetrics";
import { getIncidentEscalationSnapshot } from "../services/incidentEscalationService";
import { logger } from "../middleware/observability";

export const incidentsRouter = Router();

function isValidUuid(v: unknown): v is string {
    return typeof v === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
}

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
        }).catch(() => { });
        const status = err?.status ?? 403;
        res.status(status).json({ error: status === 401 ? "UNAUTHORIZED" : "FORBIDDEN", detail: err?.message ?? "Forbidden" });
        return false;
    }
}

// GET /v1/incidents
incidentsRouter.get("/v1/incidents", authenticateApiKey, async (req, res, next) => {
    if (!(await guardRole(req, res, "VIEWER"))) return;
    try {
        const tenantId = req.auth?.tenantId;
        if (!tenantId) return res.status(401).json({ error: "API key required" });

        const status = req.query?.status ? String(req.query.status).toUpperCase() : undefined;
        if (status && !["OPEN", "ACKED", "RESOLVED"].includes(status)) {
            return res.status(400).json({ error: "status must be OPEN, ACKED, or RESOLVED" });
        }

        const type = req.query?.type ? String(req.query.type).toUpperCase() : undefined;
        const severityMin = req.query?.severity_min ? String(req.query.severity_min).toUpperCase() : undefined;
        if (severityMin && !["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(severityMin)) {
            return res.status(400).json({ error: "severity_min must be LOW, MEDIUM, HIGH, or CRITICAL" });
        }

        const destinationKey = req.query?.destination_key ? String(req.query.destination_key) : undefined;
        const limitRaw = Number(req.query?.limit ?? 50);
        const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 200) : 50;

        let cursorOpenedAt: string | null = null;
        let cursorId: string | null = null;
        const cursor = req.query?.cursor;
        if (cursor) {
            try {
                const decoded = Buffer.from(String(cursor), "base64").toString("utf8");
                const [openedAtIso, cId] = decoded.split("|");
                if (openedAtIso && cId && !Number.isNaN(Date.parse(openedAtIso))) {
                    cursorOpenedAt = openedAtIso;
                    cursorId = cId;
                } else {
                    return res.status(400).json({ error: "Invalid cursor" });
                }
            } catch {
                return res.status(400).json({ error: "Invalid cursor" });
            }
        }

        const filters = {
            tenantId,
            status: status as any,
            type,
            severityMin,
            destinationKey,
            cursorOpenedAt,
            cursorId,
            limit,
        };

        const [result, summary] = await Promise.all([
            listIncidents(filters),
            getIncidentsSummary({ tenantId }),
        ]);

        res.json({ version: "1", ...result, summary });
    } catch (err) {
        logger.error("Failed to list incidents", { err });
        next(err);
    }
});

// GET /v1/incidents/metrics
incidentsRouter.get("/v1/incidents/metrics", authenticateApiKey, async (req, res, next) => {
    if (!(await guardRole(req, res, "VIEWER"))) return;
    try {
        const tenantId = req.auth?.tenantId;
        if (!tenantId) return res.status(401).json({ error: "API key required" });

        const metrics = await getIncidentMetricsV1({ tenantId });
        res.json(metrics);
    } catch (err) {
        logger.error("Failed to get incident metrics", { err });
        next(err);
    }
});

// GET /v1/incidents/:id
incidentsRouter.get("/v1/incidents/:id", authenticateApiKey, async (req, res, next) => {
    if (!(await guardRole(req, res, "VIEWER"))) return;
    try {
        const tenantId = req.auth?.tenantId;
        if (!tenantId) return res.status(401).json({ error: "API key required" });

        const id = String(req.params.id ?? "");
        if (!isValidUuid(id)) return res.status(400).json({ error: "Invalid incident id" });

        const incident = await getIncidentById(tenantId, id);
        if (!incident) return res.status(404).json({ error: "INCIDENT_NOT_FOUND" });

        const escalationSnapshot = await getIncidentEscalationSnapshot({ tenantId, incident, now: new Date() }).catch(() => null);
        res.json({ version: "1", item: incident, escalation_snapshot: escalationSnapshot });
    } catch (err) {
        logger.error("Failed to fetch incident", { err });
        next(err);
    }
});

// POST /v1/incidents/:id/ack
incidentsRouter.post("/v1/incidents/:id/ack", authenticateApiKey, async (req, res, next) => {
    if (!(await guardRole(req, res, "OPERATOR"))) return;
    try {
        const tenantId = req.auth?.tenantId;
        const apiKeyId = req.auth?.apiKeyId ?? null;
        if (!tenantId) return res.status(401).json({ error: "API key required" });

        const id = String(req.params.id ?? "");
        if (!isValidUuid(id)) return res.status(400).json({ error: "Invalid incident id" });

        const existing = await getIncidentById(tenantId, id);
        if (!existing) return res.status(404).json({ error: "INCIDENT_NOT_FOUND" });
        if ((existing as any).status === "RESOLVED") return res.status(409).json({ error: "INCIDENT_ALREADY_RESOLVED" });
        if ((existing as any).status === "ACKED") return res.json({ version: "1", status: "ALREADY_ACKED", item: existing });

        const now = new Date();
        const actorId = apiKeyId && isValidUuid(apiKeyId) ? apiKeyId : null;
        await db
            .update(incidents)
            .set({ status: "ACKED", ackedAt: now, ackedByActorType: "API_KEY", ackedByActorId: actorId })
            .where(and(eq(incidents.id, id), eq(incidents.tenantId, tenantId)));

        const updated = await getIncidentById(tenantId, id);

        await writeAuditEvent(req.auditContext, {
            action: "INCIDENT.ACKNOWLEDGED",
            resourceType: "INCIDENT",
            resourceId: id,
            status: "SUCCESS",
            severity: "INFO",
            message: "Incident acknowledged",
            metadata: { incident_id: id, note: req.body?.note ?? null },
        }).catch(() => { });

        logOpsEvent("INCIDENT_ACKED", {
            tenantId,
            incidentId: id,
            type: (existing as any).type,
            destinationKey: (existing as any).destinationKey ?? null,
            actorType: "API_KEY",
            actorApiKeyId: apiKeyId,
        });

        res.json({ version: "1", status: "ACKED", item: updated });
    } catch (err) {
        logger.error("Failed to acknowledge incident", { err });
        next(err);
    }
});

// POST /v1/incidents/:id/resolve
incidentsRouter.post("/v1/incidents/:id/resolve", authenticateApiKey, async (req, res, next) => {
    if (!(await guardRole(req, res, "OPERATOR"))) return;
    try {
        const tenantId = req.auth?.tenantId;
        const apiKeyId = req.auth?.apiKeyId ?? null;
        if (!tenantId) return res.status(401).json({ error: "API key required" });

        const id = String(req.params.id ?? "");
        if (!isValidUuid(id)) return res.status(400).json({ error: "Invalid incident id" });

        const existing = await getIncidentById(tenantId, id);
        if (!existing) return res.status(404).json({ error: "INCIDENT_NOT_FOUND" });
        if (!["OPEN", "ACKED"].includes(String((existing as any).status))) {
            return res.status(409).json({ error: "INCIDENT_NOT_OPEN" });
        }

        const now = new Date();
        const actorId = apiKeyId && isValidUuid(apiKeyId) ? apiKeyId : null;
        await db
            .update(incidents)
            .set({ status: "RESOLVED", resolvedAt: now, resolvedByActorType: "API_KEY", resolvedByActorId: actorId })
            .where(and(eq(incidents.id, id), eq(incidents.tenantId, tenantId)));

        const updated = await getIncidentById(tenantId, id);

        await writeAuditEvent(req.auditContext, {
            action: "INCIDENT.RESOLVED",
            resourceType: "INCIDENT",
            resourceId: id,
            status: "SUCCESS",
            severity: "SECURITY",
            message: "Incident resolved",
            metadata: { type: (existing as any).type, destination_key: (existing as any).destinationKey ?? null },
        }).catch(() => { });

        logOpsEvent("INCIDENT_RESOLVED", {
            tenantId,
            incidentId: id,
            type: (existing as any).type,
            destinationKey: (existing as any).destinationKey ?? null,
            actorType: "API_KEY",
            actorApiKeyId: apiKeyId,
        });

        res.json({ version: "1", status: "RESOLVED", item: updated });
    } catch (err) {
        logger.error("Failed to resolve incident", { err });
        next(err);
    }
});
