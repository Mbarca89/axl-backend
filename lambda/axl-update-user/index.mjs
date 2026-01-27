import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  UpdateCommand,
  GetCommand,
  QueryCommand,
} from "@aws-sdk/lib-dynamodb";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const USERS_TABLE = process.env.USERS_TABLE || "Users";
const USERNAME_INDEX = process.env.USERNAME_INDEX || "GSI_Username";
const EMAIL_INDEX = process.env.EMAIL_INDEX || "GSI_Email";
const JWT_SECRET = process.env.JWT_SECRET;

function json(statusCode, body) {
  return {
    statusCode,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  };
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}
function normalizeUsername(u) {
  return String(u || "").trim().toLowerCase();
}

function requireAuth(event) {
  const auth = event.headers?.authorization || event.headers?.Authorization || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) {
    const e = new Error("No autorizado");
    e.statusCode = 401;
    throw e;
  }
  try {
    return jwt.verify(m[1], JWT_SECRET);
  } catch {
    const e = new Error("Token inválido");
    e.statusCode = 401;
    throw e;
  }
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
    const auth = requireAuth(event);
    const userId = auth.sub;

    const body = event.body ? JSON.parse(event.body) : {};

    // 1) Traigo user actual para comparar (username/email)
    const currentRes = await ddb.send(
      new GetCommand({
        TableName: USERS_TABLE,
        Key: { userId },
      })
    );

    const current = currentRes.Item;
    if (!current) {
      return json(404, { message: "Usuario no encontrado" });
    }

    // 2) Armo cambios permitidos
    // Campos editables (ajustá si querés permitir/denegar alguno)
    const editable = {
      firstname: body.firstname,
      surname: body.surname,
      phone: body.phone,
      dni: body.dni,
      birthDate: body.birthDate, // YYYY-MM-DD
      position: body.position,
      side: body.side,
      number: body.number,
      avatarKey: body.avatarKey, // si lo usás
    };

    // Username/email/password aparte
    const newUsername =
      body.username !== undefined ? normalizeUsername(body.username) : undefined;
    const newEmail =
      body.email !== undefined ? normalizeEmail(body.email) : undefined;
    const newPassword = body.password !== undefined ? String(body.password) : undefined;

    // 3) Validaciones
    // username unique si cambió
    if (newUsername !== undefined) {
      if (!newUsername) return json(400, { message: "Username inválido" });

      if (newUsername !== current.username) {
        if (await existsByIndex(USERNAME_INDEX, "username", newUsername)) {
          return json(409, { message: "Ese usuario ya existe" });
        }
      }
    }

    // email unique si cambió
    if (newEmail !== undefined) {
      if (!newEmail) return json(400, { message: "Email inválido" });

      if (newEmail !== current.email) {
        if (await existsByIndex(EMAIL_INDEX, "email", newEmail)) {
          return json(409, { message: "Ese email ya está registrado" });
        }
      }
    }

    // password
    let passwordHash;
    if (newPassword !== undefined) {
      if (newPassword.length < 6) {
        return json(400, { message: "La contraseña debe tener al menos 6 caracteres" });
      }
      passwordHash = await bcrypt.hash(newPassword, 10);
    }

    // 4) Construyo UpdateExpression dinámico (solo lo que vino)
    const sets = [];
    const names = {};
    const values = {};

    const now = new Date().toISOString();
    names["#updatedAt"] = "updatedAt";
    values[":updatedAt"] = now;
    sets.push("#updatedAt = :updatedAt");

    // username/email si vinieron
    if (newUsername !== undefined) {
      names["#username"] = "username";
      values[":username"] = newUsername;
      sets.push("#username = :username");
    }
    if (newEmail !== undefined) {
      names["#email"] = "email";
      values[":email"] = newEmail;
      sets.push("#email = :email");
    }
    if (passwordHash !== undefined) {
      names["#passwordHash"] = "passwordHash";
      values[":passwordHash"] = passwordHash;
      sets.push("#passwordHash = :passwordHash");
    }

    // resto de campos editables
    for (const [k, v] of Object.entries(editable)) {
      if (v !== undefined) {
        names[`#${k}`] = k;
        values[`:${k}`] = v ?? null; // si mandan null, lo guardo null
        sets.push(`#${k} = :${k}`);
      }
    }

    // Si no hay nada para actualizar (solo updatedAt no cuenta?)
    if (sets.length === 1) {
      return json(400, { message: "No hay cambios para aplicar" });
    }

    const updateRes = await ddb.send(
      new UpdateCommand({
        TableName: USERS_TABLE,
        Key: { userId },
        UpdateExpression: `SET ${sets.join(", ")}`,
        ExpressionAttributeNames: names,
        ExpressionAttributeValues: values,
        ConditionExpression: "attribute_exists(userId)",
        ReturnValues: "ALL_NEW",
      })
    );

    const updated = updateRes.Attributes;

    // 5) Respuesta sin passwordHash
    const safeUser = {
      userId: updated.userId,
      username: updated.username,
      email: updated.email,
      role: updated.role,
      firstname: updated.firstname ?? null,
      surname: updated.surname ?? null,
      phone: updated.phone ?? null,
      dni: updated.dni ?? null,
      birthDate: updated.birthDate ?? null,
      position: updated.position ?? null,
      side: updated.side ?? null,
      number: updated.number ?? null,
      avatarKey: updated.avatarKey ?? null,
      playerCode: updated.playerCode, // si lo querés exponer
      createdAt: updated.createdAt,
      updatedAt: updated.updatedAt,
    };

    return json(200, { message: "Perfil actualizado", user: safeUser });
  } catch (err) {
    console.error(err);
    return json(err.statusCode || 500, { message: err.message || "Error interno" });
  }
};
