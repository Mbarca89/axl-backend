import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb";
import jwt from "jsonwebtoken";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const TEAM_INVITES_TABLE = process.env.TEAM_INVITES_TABLE;
const USER_INVITES_INDEX = process.env.USER_INVITES_INDEX || "GSI_UserInvites";
const JWT_SECRET = process.env.JWT_SECRET;

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "OPTIONS,GET",
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

    // opcional: ?status=PENDING
    const qs = event.queryStringParameters || {};
    const status = (qs.status || "PENDING").toUpperCase();

    const res = await ddb.send(
      new QueryCommand({
        TableName: TEAM_INVITES_TABLE,
        IndexName: USER_INVITES_INDEX,
        KeyConditionExpression: "#u = :uid",
        ExpressionAttributeNames: { "#u": "toUserId" },
        ExpressionAttributeValues: { ":uid": auth.sub },
        ScanIndexForward: false, // más nuevas primero si SK es createdAt
      })
    );

    let items = res.Items || [];

    // Filtrado por status (como no pusimos status en la key del índice, filtramos en memoria)
    if (status && status !== "ALL") {
      items = items.filter((i) => i.status === status);
    }

    // respuesta prolija
    const invites = items.map((i) => ({
      teamId: i.teamId,
      inviteId: i.inviteId,
      inviteRole: i.inviteRole,
      status: i.status,
      createdAt: i.createdAt,
      createdByUserId: i.createdByUserId,
    }));

    return json(200, { message: "OK", invites });
  } catch (err) {
    console.error(err);
    return json(err.statusCode || 500, { message: err.message || "Error interno" });
  }
};
