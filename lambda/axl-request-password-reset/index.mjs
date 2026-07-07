import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  PutCommand,
  QueryCommand,
} from "@aws-sdk/lib-dynamodb";
import crypto from "crypto";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const USERS_TABLE = process.env.USERS_TABLE || "Users";
const EMAIL_INDEX = process.env.EMAIL_INDEX || "GSI_Email";
const PASSWORD_RESET_TOKENS_TABLE =
  process.env.PASSWORD_RESET_TOKENS_TABLE || "PasswordResetTokens";
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const RESET_PASSWORD_BASE_URL = process.env.RESET_PASSWORD_BASE_URL;
const RESET_FROM_EMAIL = process.env.RESET_FROM_EMAIL || "soporte@axlpaintball.com.ar";

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  };
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

async function findUserByEmail(email) {
  const res = await ddb.send(
    new QueryCommand({
      TableName: USERS_TABLE,
      IndexName: EMAIL_INDEX,
      KeyConditionExpression: "#email = :email",
      ExpressionAttributeNames: { "#email": "email" },
      ExpressionAttributeValues: { ":email": email },
      Limit: 1,
    })
  );
  return res.Items?.[0] ?? null;
}

async function sendResetEmail(to, resetLink) {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${RESEND_API_KEY}`,
    },
    body: JSON.stringify({
      from: RESET_FROM_EMAIL,
      to: [to],
      subject: "Recuperar contraseña - AXL Paintball",
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.5;">
          <h2>Recuperar contraseña</h2>
          <p>Recibimos una solicitud para restablecer tu contraseña.</p>
          <p>
            Hacé click en el siguiente enlace para continuar:
          </p>
          <p>
            <a href="${resetLink}" target="_blank">${resetLink}</a>
          </p>
          <p>Este enlace expira en 1 hora.</p>
          <p>Si no solicitaste este cambio, podés ignorar este correo.</p>
        </div>
      `,
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Resend error: ${text}`);
  }
}

export const handler = async (event) => {
  if (event.requestContext?.http?.method === "OPTIONS") {
    return json(200, { ok: true });
  }

  try {
    if (!RESEND_API_KEY) {
      return json(500, { message: "Falta RESEND_API_KEY" });
    }
    if (!RESET_PASSWORD_BASE_URL) {
      return json(500, { message: "Falta RESET_PASSWORD_BASE_URL" });
    }

    const body = event.body ? JSON.parse(event.body) : {};
    const email = normalizeEmail(body.email);

    if (!email) {
      return json(400, { message: "Falta email" });
    }

    const user = await findUserByEmail(email);

    // Respuesta genérica para no revelar si existe o no
    if (!user) {
      return json(200, {
        message: "Si el email existe, se enviará un enlace para restablecer la contraseña.",
      });
    }

    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

    const now = new Date();
    const expiresAt = Math.floor((now.getTime() + 60 * 60 * 1000) / 1000); // 1 hora

    await ddb.send(
      new PutCommand({
        TableName: PASSWORD_RESET_TOKENS_TABLE,
        Item: {
          tokenHash,
          userId: user.userId,
          email,
          createdAt: now.toISOString(),
          expiresAt,
          used: false,
        },
      })
    );

    const resetLink = `${RESET_PASSWORD_BASE_URL}?token=${encodeURIComponent(rawToken)}`;

    await sendResetEmail(email, resetLink);

    return json(200, {
      message: "Si el email existe, se enviará un enlace para restablecer la contraseña.",
    });
  } catch (err) {
    console.error(err);
    return json(500, { message: "Error interno" });
  }
};