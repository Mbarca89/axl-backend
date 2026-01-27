import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  QueryCommand,
  BatchGetCommand,
} from "@aws-sdk/lib-dynamodb";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import jwt from "jsonwebtoken";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const s3 = new S3Client({});

const TEAMS_TABLE = process.env.TEAMS_TABLE;
const TEAM_MEMBERS_TABLE = process.env.TEAM_MEMBERS_TABLE;
const USERS_TABLE = process.env.USERS_TABLE;
const JWT_SECRET = process.env.JWT_SECRET;

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

async function signGetUrl(key) {
  if (!S3_BUCKET || !key) return null;
  return await getSignedUrl(
    s3,
    new GetObjectCommand({ Bucket: S3_BUCKET, Key: key }),
    { expiresIn: SIGNED_URL_TTL_SECONDS }
  );
}

export const handler = async (event) => {
  if (event.requestContext?.http?.method === "OPTIONS") return json(200, { ok: true });

  try {
    requireAuth(event);

    const qs = event.queryStringParameters || {};
    const teamId = String(qs.teamId || "").trim();
    if (!teamId) return json(400, { message: "Falta teamId" });

    // Team
    const teamRes = await ddb.send(new GetCommand({ TableName: TEAMS_TABLE, Key: { teamId } }));
    const team = teamRes.Item;
    if (!team) return json(404, { message: "Team no encontrado" });

    // Members
    const memRes = await ddb.send(
      new QueryCommand({
        TableName: TEAM_MEMBERS_TABLE,
        KeyConditionExpression: "teamId = :t AND begins_with(sk, :p)",
        ExpressionAttributeValues: { ":t": teamId, ":p": "USER#" },
      })
    );

    const memberships = (memRes.Items || []).filter((m) => m.status === "ACTIVE");

    // BatchGet Users
    const userIds = [...new Set(memberships.map((m) => m.userId))];

    let users = [];
    if (userIds.length > 0) {
      const batch = await ddb.send(
        new BatchGetCommand({
          RequestItems: {
            [USERS_TABLE]: {
              Keys: userIds.map((userId) => ({ userId })),
              ProjectionExpression: "userId, username, firstname, surname, avatarKey",
            },
          },
        })
      );
      users = batch.Responses?.[USERS_TABLE] || [];
    }

    const userById = new Map(users.map((u) => [u.userId, u]));

    const logoUrl = team.logoKey ? await signGetUrl(team.logoKey) : null;

    async function mapMember(m) {
      const u = userById.get(m.userId) || {};
      const avatarUrl = u.avatarKey ? await signGetUrl(u.avatarKey) : null;

      return {
        userId: m.userId,
        accessRole: m.accessRole,
        teamRole: m.teamRole,
        username: u.username ?? null,
        firstname: u.firstname ?? null,
        surname: u.surname ?? null,
        avatarUrl,
        joinedAt: m.joinedAt ?? null,
      };
    }

    const players = await Promise.all(
      memberships.filter((m) => m.teamRole === "PLAYER").map(mapMember)
    );
    const staff = await Promise.all(
      memberships.filter((m) => m.teamRole === "STAFF").map(mapMember)
    );

    return json(200, {
      message: "OK",
      team: {
        teamId: team.teamId,
        teamName: team.teamName,
        country: team.country ?? null,
        province: team.province ?? null,
        ownerUserId: team.ownerUserId,
        logoUrl,
      },
      players,
      staff,
    });
  } catch (err) {
    console.error(err);
    return json(err.statusCode || 500, { message: err.message || "Error interno" });
  }
};