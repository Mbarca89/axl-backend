import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const USERS_TABLE = process.env.USERS_TABLE || "Users";
const PASSWORD_RESET_TOKENS_TABLE =
  process.env.PASSWORD_RESET_TOKENS_TABLE || "PasswordResetTokens";

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  };
}

export const handler = async (event) => {
  if (event.requestContext?.http?.method === "OPTIONS") {
    return json(200, { ok: true });
  }

  try {
    const body = event.body ? JSON.parse(event.body) : {};
    const token = String(body.token || "").trim();
    const newPassword = String(body.newPassword || "");

    if (!token || !newPassword) {
      return json(400, { message: "Faltan token y/o newPassword" });
    }

    if (newPassword.length < 6) {
      return json(400, { message: "La contraseña debe tener al menos 6 caracteres" });
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const tokenRes = await ddb.send(
      new GetCommand({
        TableName: PASSWORD_RESET_TOKENS_TABLE,
        Key: { tokenHash },
      })
    );

    const tokenItem = tokenRes.Item;
    if (!tokenItem) {
      return json(400, { message: "Token inválido o expirado" });
    }

    const nowEpoch = Math.floor(Date.now() / 1000);

    if (tokenItem.used) {
      return json(400, { message: "El token ya fue utilizado" });
    }

    if (tokenItem.expiresAt < nowEpoch) {
      return json(400, { message: "Token inválido o expirado" });
    }

    const newHash = await bcrypt.hash(newPassword, 10);

    await ddb.send(
      new UpdateCommand({
        TableName: USERS_TABLE,
        Key: { userId: tokenItem.userId },
        UpdateExpression: "SET passwordHash = :ph, updatedAt = :u",
        ExpressionAttributeValues: {
          ":ph": newHash,
          ":u": new Date().toISOString(),
        },
        ConditionExpression: "attribute_exists(userId)",
      })
    );

    await ddb.send(
      new UpdateCommand({
        TableName: PASSWORD_RESET_TOKENS_TABLE,
        Key: { tokenHash },
        UpdateExpression: "SET used = :used",
        ExpressionAttributeValues: {
          ":used": true,
        },
      })
    );

    return json(200, { message: "Contraseña actualizada correctamente" });
  } catch (err) {
    console.error(err);
    return json(500, { message: "Error interno" });
  }
};