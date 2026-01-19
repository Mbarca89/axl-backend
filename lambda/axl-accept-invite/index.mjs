import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
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

    if (invite.status !== "PENDING") {
      return json(409, { message: `La invitación ya está en estado ${invite.status}` });
    }

    if (invite.toUserId !== auth.sub) {
      return json(403, { message: "No podés aceptar una invitación que no es tuya" });
    }

    const now = new Date().toISOString();

    // 2) Crear miembro (si no existe)
    await ddb.send(new PutCommand({
      TableName: TEAM_MEMBERS_TABLE,
      Item: {
        teamId,
        sk: `USER#${auth.sub}`,
        userId: auth.sub,
        accessRole: "MEMBER",
        teamRole: invite.inviteRole === "STAFF" ? "STAFF" : "PLAYER",
        status: "ACTIVE",
        joinedAt: now,
      },
      ConditionExpression: "attribute_not_exists(sk)",
    }));


    // 3) Marcar invite como ACCEPTED
    await ddb.send(
      new UpdateCommand({
        TableName: TEAM_INVITES_TABLE,
        Key: { teamId, sk: `INVITE#${inviteId}` },
        UpdateExpression: "SET #st = :a, acceptedAt = :t",
        ExpressionAttributeNames: { "#st": "status" },
        ExpressionAttributeValues: { ":a": "ACCEPTED", ":t": now },
        ConditionExpression: "#st = :p",
        ExpressionAttributeValues: { ":a": "ACCEPTED", ":t": now, ":p": "PENDING" },
        ExpressionAttributeNames: { "#st": "status" },
      })
    );

    return json(200, {
      message: "Invitación aceptada",
      teamId,
      userId: auth.sub,
      teamRole: invite.inviteRole === "STAFF" ? "STAFF" : "PLAYER",
      accessRole
    });
  } catch (err) {
    console.error(err);

    // Si el PutCommand falla por condition (ya era miembro), devolvemos 409 más lindo
    if (err.name === "ConditionalCheckFailedException") {
      return json(409, { message: "Ya sos miembro de este equipo" });
    }

    return json(err.statusCode || 500, { message: err.message || "Error interno" });
  }
};
