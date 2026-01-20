import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const USERS_TABLE = process.env.USERS_TABLE || "Users";
const USERNAME_INDEX = process.env.USERNAME_INDEX || "GSI_Username";
const EMAIL_INDEX = process.env.EMAIL_INDEX || "GSI_Email";

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

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}
function normalizeUsername(u) {
  return String(u || "").trim().toLowerCase();
}

async function existsByIndex(indexName, attrName, value) {
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
  return (res.Items?.length || 0) > 0;
}

export const handler = async (event) => {
  // Preflight CORS
  if (event.requestContext?.http?.method === "OPTIONS") {
    return json(200, { ok: true });
  }

  try {
    const body = event.body ? JSON.parse(event.body) : {};
    const username = normalizeUsername(body.username);
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");

    if (!username || !email || !password) {
      return json(400, { message: "Faltan campos obligatorios: username, email, password" });
    }
    if (password.length < 6) {
      return json(400, { message: "La contraseña debe tener al menos 6 caracteres" });
    }

    // checks de unicidad
    if (await existsByIndex(USERNAME_INDEX, "username", username)) {
      return json(409, { message: "Ese usuario ya existe" });
    }
    if (await existsByIndex(EMAIL_INDEX, "email", email)) {
      return json(409, { message: "Ese email ya está registrado" });
    }

    const userId = crypto.randomUUID();
    const passwordHash = await bcrypt.hash(password, 10);
    const now = new Date().toISOString();

    const item = {
      userId,
      username,
      email,
      passwordHash,
      role: "PLAYER",
      firstname: body.firstname ?? null,
      surname: body.surname ?? null,
      phone: body.phone ?? null,
      dni: body.dni ?? null,
      birthDate: body.birthDate ?? null, // YYYY-MM-DD
      position: body.position ?? null,
      side: body.side ?? null,
      number: body.number ?? null,
      avatarUrl: null,
      createdAt: now,
      updatedAt: now,
    };

    await ddb.send(
      new PutCommand({
        TableName: USERS_TABLE,
        Item: item,
        ConditionExpression: "attribute_not_exists(userId)",
      })
    );

    return json(201, {
      message: "Registro OK",
      user: { userId, username, email, role: "PLAYER" },
    });
  } catch (err) {
    console.error(err);
    return json(500, { message: "Error interno" });
  }
};
