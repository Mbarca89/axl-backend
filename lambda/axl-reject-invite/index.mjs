import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import jwt from "jsonwebtoken";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const TEAM_INVITES_TABLE = process.env.TEAM_INVITES_TABLE;
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
  if (event.requestContext?.http?.method === "OPTIONS") return json(200, { ok: true });

  try {
    const auth = requireAuth(event);
    const body = event.body ? JSON.parse(event.body) : {};

    const teamId = String(body.teamId || "").trim();
    const inviteId = String(body.inviteId || "").trim();
    if (!teamId) return json(400, { message: "Falta teamId" });
    if (!inviteId) return json(400, { message: "Falta inviteId" });

    // 1) Traer invite
    const invRes = await ddb.send(
      new GetCommand({
        TableName: TEAM_INVITES_TABLE,
        Key: { teamId, sk: `INVITE#${inviteId}` },
      })
    );

    const invite = invRes.Item;
    if (!invite) return json(404, { message: "Invitación no encontrada" });

    if (invite.toUserId !== auth.sub) {
      return json(403, { message: "No podés rechazar una invitación que no es tuya" });
    }

    if (invite.status !== "PENDING") {
      return json(409, { message: `La invitación ya está en estado ${invite.status}` });
    }

    const now = new Date().toISOString();

    // 2) Update status -> REJECTED
    await ddb.send(
      new UpdateCommand({
        TableName: TEAM_INVITES_TABLE,
        Key: { teamId, sk: `INVITE#${inviteId}` },
        UpdateExpression: "SET #st = :r, rejectedAt = :t",
        ConditionExpression: "#st = :p",
        ExpressionAttributeNames: { "#st": "status" },
        ExpressionAttributeValues: { ":r": "REJECTED", ":t": now, ":p": "PENDING" },
      })
    );

    return json(200, { message: "Invitación rechazada", teamId, inviteId });
  } catch (err) {
    console.error(err);
    return json(err.statusCode || 500, { message: err.message || "Error interno" });
  }
};
