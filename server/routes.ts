import type { Express } from "express";
import { createServer, type Server } from "http";
import { WebSocketServer } from "ws";
import swaggerUi from "swagger-ui-express";

import { requestTrackingMiddleware, logger } from "./middleware/observability";
import { wsManager } from "./services/wsManagerService";
import { openApiSpec } from "./openapi";

import { healthRouter } from "./routers/health.router";
import { authRouter } from "./routers/auth.router";
import { devRouter, seedDemoApiKeyIfDev } from "./routers/dev.router";
import { createAdminRouter } from "./routers/admin.router";
import { mockDataService } from "./services/mockDataService";
import { signalsRouter } from "./routers/signals.router";
import { portsRouter } from "./routers/ports.router";
import { alertsRouter } from "./routers/alerts.router";
import { vesselsRouter } from "./routers/vessels.router";
import { commoditiesRouter } from "./routers/commodities.router";
import { flowsRouter } from "./routers/flows.router";
import { alertRulesRouter } from "./routers/alert-rules.router";
import { teamRouter } from "./routers/team.router";
import { auditRouter } from "./routers/audit.router";
import { destinationsRouter } from "./routers/destinations.router";
import { incidentsRouter } from "./routers/incidents.router";
import { escalationsRouter } from "./routers/escalations.router";
import { alertOpsRouter } from "./routers/alert-ops.router";

export async function registerRoutes(app: Express): Promise<Server> {
  const httpServer = createServer(app);

  // Apply observability middleware
  app.use(requestTrackingMiddleware);

  // OpenAPI documentation
  app.use("/docs", swaggerUi.serve, swaggerUi.setup(openApiSpec));
  app.get("/openapi.json", (req, res) => {
    res.json(openApiSpec);
  });

  // WebSocket setup
  const wss = new WebSocketServer({ server: httpServer, path: "/ws" });
  wsManager.initialize(wss);

  // Seed dev API key on startup (no-op in production)
  seedDemoApiKeyIfDev();

  // Seed base data (admin user, ports, vessels) — idempotent, safe to run on every boot
  if (process.env.NODE_ENV !== "production") {
    mockDataService.initializeBaseData().catch((err) => {
      logger.error("Failed to seed base data", { error: err });
    });
  }

  // Mount feature routers
  app.use("/", healthRouter);
  app.use("/", authRouter);
  if (process.env.NODE_ENV !== "production") {
    app.use("/", devRouter);
  }
  app.use("/", createAdminRouter(wss));
  app.use("/", signalsRouter);
  app.use("/", portsRouter);
  app.use("/", alertsRouter);
  app.use("/", vesselsRouter);
  app.use("/", commoditiesRouter);
  app.use("/", flowsRouter);
  app.use("/", alertRulesRouter);
  app.use("/", teamRouter);
  app.use("/", auditRouter);
  app.use("/", destinationsRouter);
  app.use("/", incidentsRouter);
  app.use("/", escalationsRouter);
  app.use("/", alertOpsRouter);

  return httpServer;
}
