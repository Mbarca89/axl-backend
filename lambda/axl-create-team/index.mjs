import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const TEAMS_TABLE = process.env.TEAMS_TABLE;
const TEAM_MEMBERS_TABLE = process.env.TEAM_MEMBERS_TABLE;
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
    const e = new Error("No autorizado");
    e.statusCode = 401;
    throw e;
  }
  try {
    return jwt.verify(m[1], JWT_SECRET);
  } catch {
    const e = new Error("Token inválido");
    e.statusCode = 401;
    throw e;
  }
}

export const handler = async (event) => {
  if (event.requestContext?.http?.method === "OPTIONS") {
    return json(200, { ok: true });
  }

  try {
    const auth = requireAuth(event);
    const body = event.body ? JSON.parse(event.body) : {};

    if (!body.teamName) {
      return json(400, { message: "Falta el nombre del equipo" });
    }

    const teamId = crypto.randomUUID();
    const now = new Date().toISOString();

    // 1) Crear equipo
    await ddb.send(new PutCommand({
      TableName: TEAMS_TABLE,
      Item: {
        teamId,
        teamName: body.teamName,
        ownerUserId: auth.sub,
        country: body.country ?? null,
        province: body.province ?? null,
        createdAt: now,
        updatedAt: now,
      },
      ConditionExpression: "attribute_not_exists(teamId)",
    }));

    // 2) Crear miembro OWNER
    await ddb.send(new PutCommand({
      TableName: TEAM_MEMBERS_TABLE,
      Item: {
        teamId,
        sk: `USER#${auth.sub}`,
        userId: auth.sub,
        accessRole: "OWNER",
        teamRole: body.teamRole || "PLAYER", 
        status: "ACTIVE",
        joinedAt: now,
      },
      ConditionExpression: "attribute_not_exists(sk)",
    }));


    return json(201, {
      message: "Equipo creado",
      team: { teamId, teamName: body.teamName },
    });
  } catch (err) {
    console.error(err);
    return json(err.statusCode || 500, { message: err.message || "Error interno" });
  }
};
