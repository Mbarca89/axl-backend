import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand } from "@aws-sdk/lib-dynamodb";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const s3 = new S3Client({});
const USERS_TABLE = process.env.USERS_TABLE;
const S3_BUCKET = process.env.S3_BUCKET;
const SIGNED_URL_TTL_SECONDS = Number(process.env.SIGNED_URL_TTL_SECONDS || "3600");

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  };
}

async function signGetUrl(key) {
  if (!S3_BUCKET || !key) return null;
  return await getSignedUrl(
    s3,
    new GetObjectCommand({ Bucket: S3_BUCKET, Key: key }),
    { expiresIn: SIGNED_URL_TTL_SECONDS }
  );
}

export const handler = async (event) => {
  if (event.requestContext?.http?.method === "OPTIONS") {
    return json(200, { ok: true });
  }

  try {
    const qs = event.queryStringParameters || {};
    const userId = String(qs.userId || "").trim();
    if (!userId) return json(400, { message: "Falta userId" });

    if (!USERS_TABLE) {
      return json(500, { message: "USERS_TABLE no configurado" });
    }

    const userRes = await ddb.send(
      new GetCommand({ TableName: USERS_TABLE, Key: { userId } })
    );

    if (!userRes.Item) {
      return json(404, { message: "Jugador no encontrado" });
    }

    const user = userRes.Item;
    const avatarUrl = user.avatarKey ? await signGetUrl(user.avatarKey) : null;

    return json(200, {
      message: "OK",
      user: {
        userId: user.userId,
        username: user.username,
        firstname: user.firstname ?? null,
        surname: user.surname ?? null,
        avatarUrl,
        birthDate: user.birthDate ?? null,
        position: user.position ?? null,
        side: user.side ?? null,
        number: user.number ?? null,
        role: user.role ?? null,
        currentRank: user.currentRank ?? null,
      },
    });
  } catch (err) {
    console.error(err);
    return json(500, { message: err.message || "Error interno" });
  }
};
