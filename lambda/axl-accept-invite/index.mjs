import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  TransactWriteCommand,
} from "@aws-sdk/lib-dynamodb";
import jwt from "jsonwebtoken";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const TEAM_INVITES_TABLE = process.env.TEAM_INVITES_TABLE;
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

export const handler = async (event) => {
  const method = event.requestContext?.http?.method || event.httpMethod || "";
  if (method === "OPTIONS") return json(200, { ok: true });
  if (method !== "POST") return json(405, { message: "Method not allowed" });

  try {
    const auth = requireAuth(event);
    const body = event.body ? JSON.parse(event.body) : {};
    const teamId = String(body.teamId || "").trim();
    if (!teamId) return json(400, { message: "Falta teamId" });

    const inviteKey = { teamId, sk: `INVITE_TO#${auth.sub}` };

    // 1) Leer invitación para obtener inviteRole
    const invRes = await ddb.send(
      new GetCommand({
        TableName: TEAM_INVITES_TABLE,
        Key: inviteKey,
      })
    );

    const invite = invRes.Item;
    if (!invite) return json(404, { message: "Invitación no encontrada" });

    if (invite.toUserId !== auth.sub) {
      return json(403, { message: "No podés aceptar una invitación que no es tuya" });
    }
    if (invite.status !== "PENDING") {
      return json(409, { message: `La invitación ya está en estado ${invite.status}` });
    }

    // role del miembro (PLAYER o STAFF). Si no vino, default PLAYER
    const teamRole = String(invite.inviteRole || "PLAYER").toUpperCase();
    if (!["PLAYER", "STAFF"].includes(teamRole)) {
      return json(400, { message: "inviteRole inválido en la invitación" });
    }

    const now = new Date().toISOString();

    // 2) Transacción: crear miembro + borrar invite (atómico)
    await ddb.send(
      new TransactWriteCommand({
        TransactItems: [
          {
            Put: {
              TableName: TEAM_MEMBERS_TABLE,
              Item: {
                teamId,
                sk: `USER#${auth.sub}`,
                userId: auth.sub,
                accessRole: "MEMBER",
                teamRole, // ✅ respeta STAFF/PLAYER
                status: "ACTIVE",
                joinedAt: now,
              },
              ConditionExpression: "attribute_not_exists(sk)",
            },
          },
          {
            Delete: {
              TableName: TEAM_INVITES_TABLE,
              Key: inviteKey,
              ConditionExpression: "#st = :p",
              ExpressionAttributeNames: { "#st": "status" },
              ExpressionAttributeValues: { ":p": "PENDING" },
            },
          },
        ],
      })
    );

    return json(200, { message: "Invitación aceptada", teamId, teamRole });
  } catch (err) {
    console.error(err);

    // Esto cubre: ya sos miembro, o la invite dejó de estar pending / no existe
    if (err?.name === "TransactionCanceledException" || err?.name === "ConditionalCheckFailedException") {
      return json(409, { message: "No se pudo aceptar (ya sos miembro o la invitación cambió)" });
    }

    return json(err.statusCode || 500, { message: err.message || "Error interno" });
  }
};