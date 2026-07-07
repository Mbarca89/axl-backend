import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, QueryCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import jwt from "jsonwebtoken";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
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
  console.info("manage-team-member:auth-header", {
    hasAuthHeader: !!auth,
    authHeaderPreview: auth ? auth.substring(0, 12) + "..." : null,
  });

  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) {
    const err = new Error("No autorizado");
    err.statusCode = 401;
    throw err;
  }
  try {
    return jwt.verify(m[1], JWT_SECRET);
  } catch {
    const err = new Error("Token inválido o expirado");
    err.statusCode = 401;
    throw err;
  }
}

async function findMembership(teamId, userId) {
  const res = await ddb.send(
    new QueryCommand({
      TableName: TEAM_MEMBERS_TABLE,
      KeyConditionExpression: "teamId = :teamId",
      ExpressionAttributeValues: { ":teamId": teamId },
      Limit: 20,
    })
  );

  return (res.Items || []).find((item) => item.userId === userId || item.sk === `USER#${userId}`) || null;
}

export const handler = async (event) => {
  if (event.requestContext?.http?.method === "OPTIONS") {
    return json(200, { ok: true });
  }

  try {
    if (!TEAM_MEMBERS_TABLE) {
      return json(500, { message: "TEAM_MEMBERS_TABLE no configurado" });
    }

    const auth = requireAuth(event);
    const body = event.body ? JSON.parse(event.body) : {};
    const teamId = String(body.teamId || "").trim();
    const memberUserId = String(body.memberUserId || "").trim();
    const action = String(body.action || "").trim().toUpperCase();

    if (!teamId || !memberUserId || !action) {
      return json(400, { message: "Faltan teamId, memberUserId o action" });
    }

    console.info("manage-team-member:start", { teamId, memberUserId, action, actorUserId: auth.sub });

    if (memberUserId === auth.sub) {
      return json(400, { message: "No podés gestionar tu propio usuario" });
    }

    const me = await findMembership(teamId, auth.sub);
    console.info("manage-team-member:actor-membership", { teamId, actorUserId: auth.sub, me: me ? { status: me.status, accessRole: me.accessRole, sk: me.sk } : null });

    if (!me || me.status !== "ACTIVE") {
      console.warn("manage-team-member:forbidden-actor-not-active", { teamId, actorUserId: auth.sub });
      return json(403, { message: "No sos miembro activo" });
    }
    if (me.accessRole !== "OWNER") {
      console.warn("manage-team-member:forbidden-actor-not-owner", { teamId, actorUserId: auth.sub, accessRole: me.accessRole });
      return json(403, { message: "Solo el OWNER puede gestionar miembros" });
    }

    const member = await findMembership(teamId, memberUserId);
    console.info("manage-team-member:target-membership", { teamId, memberUserId, member: member ? { status: member.status, accessRole: member.accessRole, sk: member.sk } : null });

    if (!member || member.status !== "ACTIVE") {
      return json(404, { message: "Miembro no encontrado" });
    }
    if (member.accessRole === "OWNER") {
      console.warn("manage-team-member:forbidden-target-owner", { teamId, memberUserId });
      return json(403, { message: "No podés cambiar al dueño del equipo" });
    }

    if (action === "SET_ROLE") {
      const teamRole = String(body.teamRole || "").trim().toUpperCase();
      if (!["PLAYER", "STAFF"].includes(teamRole)) {
        return json(400, { message: "teamRole inválido (PLAYER o STAFF)" });
      }
      await ddb.send(
        new UpdateCommand({
          TableName: TEAM_MEMBERS_TABLE,
          Key: { teamId, sk: `USER#${memberUserId}` },
          UpdateExpression: "SET teamRole = :teamRole",
          ExpressionAttributeValues: { ":teamRole": teamRole },
          ConditionExpression: "attribute_exists(teamId) AND attribute_exists(sk)",
        })
      );
      return json(200, { message: "Rol actualizado" });
    }

    if (action === "REMOVE") {
      await ddb.send(
        new UpdateCommand({
          TableName: TEAM_MEMBERS_TABLE,
          Key: { teamId, sk: `USER#${memberUserId}` },
          UpdateExpression: "SET #status = :removed",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: { ":removed": "REMOVED" },
          ConditionExpression: "attribute_exists(teamId) AND attribute_exists(sk)",
        })
      );
      return json(200, { message: "Miembro eliminado" });
    }

    return json(400, { message: "Action inválida" });
  } catch (err) {
    console.error("manage-team-member:error", err);
    return json(err.statusCode || 500, { message: err.message || "Error interno" });
  }
};
