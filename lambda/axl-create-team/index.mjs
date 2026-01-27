import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  TransactWriteCommand,
} from "@aws-sdk/lib-dynamodb";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const TEAMS_TABLE = process.env.TEAMS_TABLE;
const TEAM_MEMBERS_TABLE = process.env.TEAM_MEMBERS_TABLE;
const JWT_SECRET = process.env.JWT_SECRET;

function json(statusCode, body) {
  return {
    statusCode,
    headers: { "content-type": "application/json" },
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

function normalizeTeamName(name) {
  return String(name).trim().toLowerCase().replace(/\s+/g, " ");
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

    const teamNameNormalized = normalizeTeamName(body.teamName);
    const teamNameKey = `TEAMNAME#${teamNameNormalized}`;

    const teamId = crypto.randomUUID();
    const now = new Date().toISOString();

    await ddb.send(
      new TransactWriteCommand({
        TransactItems: [
          {
            Put: {
              TableName: TEAMS_TABLE,
              Item: {
                teamId: `TEAMNAME#${teamNameNormalized}`,
                type: "TEAM_NAME_LOCK",
                teamNameNormalized,
                teamNameOriginal: body.teamName,
                createdAt: now,
                pointsToTeamId: teamId,
              },
              ConditionExpression: "attribute_not_exists(teamId)",
            },
          },

          {
            Put: {
              TableName: TEAMS_TABLE,
              Item: {
                teamId,
                type: "TEAM",
                teamName: body.teamName,
                teamNameNormalized,
                ownerUserId: auth.sub,
                country: body.country ?? null,
                province: body.province ?? null,
                createdAt: now,
                updatedAt: now,
              },
              ConditionExpression: "attribute_not_exists(teamId)",
            },
          },

          {
            Put: {
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
            },
          },
        ],
      })
    );

    return json(201, {
      message: "Equipo creado",
      team: { teamId, teamName: body.teamName },
    });
  } catch (err) {
    console.error(err);

    const isNameTaken =
      err?.name === "TransactionCanceledException" ||
      err?.name === "ConditionalCheckFailedException";

    if (isNameTaken) {
      return json(409, { message: "Ya existe un equipo con ese nombre" });
    }

    return json(err.statusCode || 500, {
      message: err.message || "Error interno",
    });
  }
};