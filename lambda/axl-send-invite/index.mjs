import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  QueryCommand,
  PutCommand,
} from "@aws-sdk/lib-dynamodb";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const USERS_TABLE = process.env.USERS_TABLE;
const TEAMS_TABLE = process.env.TEAMS_TABLE;
const TEAM_MEMBERS_TABLE = process.env.TEAM_MEMBERS_TABLE;
const TEAM_INVITES_TABLE = process.env.TEAM_INVITES_TABLE;
const PLAYER_CODE_INDEX = process.env.PLAYER_CODE_INDEX || "GSI_PlayerCode";
const JWT_SECRET = process.env.JWT_SECRET;

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "OPTIONS,POST",
      "access-control-allow-headers": "content-type,authorization",
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

async function getTeam(teamId) {
  const res = await ddb.send(new GetCommand({ TableName: TEAMS_TABLE, Key: { teamId } }));
  return res.Item ?? null;
}

async function getMember(teamId, userId) {
  const res = await ddb.send(
    new GetCommand({
      TableName: TEAM_MEMBERS_TABLE,
      Key: { teamId, sk: `USER#${userId}` },
    })
  );
  return res.Item ?? null;
}

async function findUserByPlayerCode(playerCode) {
  const res = await ddb.send(
    new QueryCommand({
      TableName: USERS_TABLE,
      IndexName: PLAYER_CODE_INDEX,
      KeyConditionExpression: "#pc = :v",
      ExpressionAttributeNames: { "#pc": "playerCode" },
      ExpressionAttributeValues: { ":v": playerCode },
      Limit: 1,
    })
  );
  return res.Items?.[0] ?? null;
}

export const handler = async (event) => {
  if (event.requestContext?.http?.method === "OPTIONS") return json(200, { ok: true });

  try {
    const auth = requireAuth(event);
    const body = event.body ? JSON.parse(event.body) : {};

    const teamId = String(body.teamId || "").trim();
    const playerCode = String(body.playerCode || "").trim();
    const inviteRole = String(body.inviteRole || "PLAYER").toUpperCase();

    if (!teamId) return json(400, { message: "Falta teamId" });
    if (!playerCode) return json(400, { message: "Falta playerCode" });
    if (!["PLAYER", "STAFF"].includes(inviteRole)) {
      return json(400, { message: "inviteRole inválido (PLAYER o STAFF)" });
    }

    const team = await getTeam(teamId);
    if (!team) return json(404, { message: "Team no encontrado" });

    // Permiso: solo OWNER
    const meInTeam = await getMember(teamId, auth.sub);
    if (!meInTeam || meInTeam.accessRole !== "OWNER") {
      return json(403, { message: "Solo el OWNER puede invitar" });
    }

    const targetUser = await findUserByPlayerCode(playerCode);
    if (!targetUser) return json(404, { message: "No existe jugador con ese playerCode" });

    if (targetUser.userId === auth.sub) {
      return json(400, { message: "No podés invitarte a vos mismo" });
    }

    // Evitar invitar si ya es miembro
    const already = await getMember(teamId, targetUser.userId);
    if (already && already.status !== "REMOVED") {
      return json(409, { message: "Ese usuario ya es miembro del equipo" });
    }

    const inviteId = crypto.randomUUID();
    const now = new Date().toISOString();

    await ddb.send(
      new PutCommand({
        TableName: TEAM_INVITES_TABLE,
        Item: {
          teamId,
          sk: `INVITE#${inviteId}`,
          inviteId,
          toUserId: targetUser.userId,
          inviteRole,
          status: "PENDING",
          createdByUserId: auth.sub,
          createdAt: now,
        },
        ConditionExpression: "attribute_not_exists(sk)",
      })
    );

    return json(201, {
      message: "Invitación creada",
      invite: {
        inviteId,
        teamId,
        toUserId: targetUser.userId,
        inviteRole,
        status: "PENDING",
        createdAt: now,
      },
    });
  } catch (err) {
    console.error(err);
    return json(err.statusCode || 500, { message: err.message || "Error interno" });
  }
};
