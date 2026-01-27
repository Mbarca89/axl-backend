import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const USERS_TABLE = process.env.USERS_TABLE || "Users";
const USERNAME_INDEX = process.env.USERNAME_INDEX || "GSI_Username";
const EMAIL_INDEX = process.env.EMAIL_INDEX || "GSI_Email";

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  };
}

async function findByIndex(indexName, attrName, value) {
  const res = await ddb.send(
    new QueryCommand({
      TableName: USERS_TABLE,
      IndexName: indexName,
      KeyConditionExpression: "#k = :v",
      ExpressionAttributeNames: { "#k": attrName },
      ExpressionAttributeValues: { ":v": value },
      Limit: 1,
    })
  );
  return res.Items?.[0] ?? null;
}

export const handler = async (event) => {
  // Preflight CORS
  if (event.requestContext?.http?.method === "OPTIONS") {
    return json(200, { ok: true });
  }

  try {
    if (!JWT_SECRET || JWT_SECRET.length < 20) {
      return json(500, { message: "JWT_SECRET no configurado o es muy corto" });
    }

    const body = event.body ? JSON.parse(event.body) : {};
    const loginRaw = String(body.login || "").trim();
    const password = String(body.password || "");

    if (!loginRaw || !password) {
      return json(400, { message: "Faltan campos: login y password" });
    }

    const isEmail = loginRaw.includes("@");
    const login = isEmail ? loginRaw.toLowerCase() : loginRaw.toLowerCase();

    const user = isEmail
      ? await findByIndex(EMAIL_INDEX, "email", login)
      : await findByIndex(USERNAME_INDEX, "username", login);

    if (!user) return json(401, { message: "Credenciales inválidas" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return json(401, { message: "Credenciales inválidas" });

    // JWT payload mínimo
    const token = jwt.sign(
      { sub: user.userId, role: user.role, username: user.username },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    return json(200, {
      message: "Login OK",
      token,
      user: {
        userId: user.userId,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error(err);
    return json(500, { message: "Error interno" });
  }
};
