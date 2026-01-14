import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand } from "@aws-sdk/lib-dynamodb";
import jwt from "jsonwebtoken";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const USERS_TABLE = process.env.USERS_TABLE || "Users";
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

// Helper reusable
function requireAuth(event, { roles } = {}) {
  if (!JWT_SECRET || JWT_SECRET.length < 20) {
    const err = new Error("JWT_SECRET no configurado");
    err.statusCode = 500;
    throw err;
  }

  const auth = event.headers?.authorization || event.headers?.Authorization || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) {
    const err = new Error("Falta Authorization: Bearer <token>");
    err.statusCode = 401;
    throw err;
  }

  let payload;
  try {
    payload = jwt.verify(m[1], JWT_SECRET);
  } catch {
    const err = new Error("Token inválido o expirado");
    err.statusCode = 401;
    throw err;
  }

  // payload esperado: { sub, role, username, iat, exp }
  const userId = payload.sub;
  const role = payload.role;

  if (!userId || !role) {
    const err = new Error("Token inválido (payload incompleto)");
    err.statusCode = 401;
    throw err;
  }

  if (roles && roles.length > 0 && !roles.includes(role)) {
    const err = new Error("No tenés permisos para esta acción");
    err.statusCode = 403;
    throw err;
  }

  return { userId, role, username: payload.username };
}

export const handler = async (event) => {
  // Preflight CORS
  if (event.requestContext?.http?.method === "OPTIONS") {
    return json(200, { ok: true });
  }

  try {
    // 1) auth
    const auth = requireAuth(event); // sin roles, cualquiera logueado

    // 2) traer user por PK
    const res = await ddb.send(
      new GetCommand({
        TableName: USERS_TABLE,
        Key: { userId: auth.userId },
      })
    );

    if (!res.Item) {
      return json(404, { message: "Usuario no encontrado" });
    }

    // 3) sanitizar (nunca devolvemos passwordHash)
    const { passwordHash, ...safeUser } = res.Item;

    return json(200, { message: "OK", user: safeUser });
  } catch (err) {
    const statusCode = err.statusCode || 500;
    const message = err.message || "Error interno";
    return json(statusCode, { message });
  }
};
