import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
} from "@aws-sdk/lib-dynamodb";
import jwt from "jsonwebtoken";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const EVENTS_TABLE = process.env.EVENTS_TABLE;
const EVENT_REGISTRATIONS_TABLE = process.env.EVENT_REGISTRATIONS_TABLE;
const TEAM_MEMBERS_TABLE = process.env.TEAM_MEMBERS_TABLE;
const TEAMS_TABLE = process.env.TEAMS_TABLE;
const JWT_SECRET = process.env.JWT_SECRET;

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  };
}

function requireAuth(event) {
  const auth = event.headers?.authorization || event.headers?.Authorization || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) {
    const e = new Error("Falta Authorization: Bearer <token>");
    e.statusCode = 401;
    throw e;
  }
  try {
    return jwt.verify(m[1], JWT_SECRET);
  } catch {
    const e = new Error("Token inválido o expirado");
    e.statusCode = 401;
    throw e;
  }
}

async function getEvent(eventId) {
  const res = await ddb.send(new GetCommand({ TableName: EVENTS_TABLE, Key: { eventId } }));
  return res.Item ?? null;
}

async function getTeam(teamId) {
  const res = await ddb.send(new GetCommand({ TableName: TEAMS_TABLE, Key: { teamId } }));
  return res.Item ?? null;
}

async function getMyTeamMember(teamId, userId) {
  const res = await ddb.send(
    new GetCommand({
      TableName: TEAM_MEMBERS_TABLE,
      Key: { teamId, sk: `USER#${userId}` },
    })
  );
  return res.Item ?? null;
}

export const handler = async (event) => {
  const method = event.requestContext?.http?.method || event.httpMethod || "";
  if (method === "OPTIONS") return json(200, { ok: true });
  if (method !== "POST") return json(405, { message: "Method not allowed" });

  try {
    const auth = requireAuth(event);
    const body = event.body ? JSON.parse(event.body) : {};

    const eventId = String(body.eventId || "").trim();
    const teamId = String(body.teamId || "").trim();
    const category = String(body.category || "").trim();

    if (!eventId) return json(400, { message: "Falta eventId" });
    if (!teamId) return json(400, { message: "Falta teamId" });
    if (!category) return json(400, { message: "Falta category" });

    // 1) Evento
    const ev = await getEvent(eventId);
    if (!ev) return json(404, { message: "Evento no encontrado" });
    if (ev.status !== "REGISTRATION_OPEN") {
      return json(409, { message: `Inscripciones cerradas (status=${ev.status})` });
    }
    const categories = Array.isArray(ev.categories) ? ev.categories : [];
    if (!categories.includes(category)) {
      return json(400, { message: "Categoría inválida para este evento" });
    }

    // 2) Permiso OWNER
    const me = await getMyTeamMember(teamId, auth.sub);
    if (!me || me.accessRole !== "OWNER") {
      return json(403, { message: "Solo el OWNER puede inscribir al equipo" });
    }

    // 3) Team snapshot
    const team = await getTeam(teamId);
    if (!team) return json(404, { message: "Team no encontrado" });

    const teamNameSnapshot = String(team.teamName || team.name || "").trim();
    if (!teamNameSnapshot) return json(500, { message: "El equipo no tiene nombre (teamName)" });

    // 4) Put inscripción (1 por team por event)
    const now = new Date().toISOString();
    const sk = `TEAM#${teamId}`;

    await ddb.send(
      new PutCommand({
        TableName: EVENT_REGISTRATIONS_TABLE,
        Item: {
          eventId,
          sk,
          teamId,
          teamNameSnapshot,
          category,
          registeredByUserId: auth.sub,
          status: "REGISTERED",
          registeredAt: now,
          updatedAt: now,
        },
        ConditionExpression: "attribute_not_exists(sk)",
      })
    );

    return json(201, {
      message: "Equipo inscripto",
      registration: { eventId, teamId, teamNameSnapshot, category, status: "REGISTERED" },
    });
  } catch (err) {
    console.error(err);

    if (err?.name === "ConditionalCheckFailedException") {
      return json(409, { message: "Ese equipo ya está inscripto en este evento" });
    }

    return json(err.statusCode || 500, { message: err.message || "Error interno" });
  }
};
