import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, DeleteCommand } from "@aws-sdk/lib-dynamodb";
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
  const method = event.requestContext?.http?.method || event.httpMethod || "";
  if (method === "OPTIONS") return json(200, { ok: true });
  if (method !== "POST") return json(405, { message: "Method not allowed" });

  try {
    const auth = requireAuth(event);
    const body = event.body ? JSON.parse(event.body) : {};
    const teamId = String(body.teamId || "").trim();

    if (!teamId) return json(400, { message: "Falta teamId" });

    const key = { teamId, sk: `INVITE_TO#${auth.sub}` };

    await ddb.send(
      new DeleteCommand({
        TableName: TEAM_INVITES_TABLE,
        Key: key,
        // solo borra si existía y estaba pending
        ConditionExpression: "#st = :p",
        ExpressionAttributeNames: { "#st": "status" },
        ExpressionAttributeValues: { ":p": "PENDING" },
      })
    );

    return json(200, { message: "Invitación rechazada", teamId });
  } catch (err) {
    console.error(err);

    if (err?.name === "ConditionalCheckFailedException") {
      // o no existe, o no estaba PENDING
      return json(404, { message: "No tenés una invitación pendiente para ese equipo" });
    }

    return json(err.statusCode || 500, { message: err.message || "Error interno" });
  }
};
