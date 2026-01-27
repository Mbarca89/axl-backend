import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, QueryCommand, BatchGetCommand } from "@aws-sdk/lib-dynamodb";
import jwt from "jsonwebtoken";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const s3 = new S3Client({});

const S3_BUCKET = process.env.S3_BUCKET;
const SIGNED_URL_TTL_SECONDS = Number(process.env.SIGNED_URL_TTL_SECONDS || "3600");

const TEAMS_TABLE = process.env.TEAMS_TABLE;
const TEAM_MEMBERS_TABLE = process.env.TEAM_MEMBERS_TABLE;
const USER_TEAMS_INDEX = process.env.USER_TEAMS_INDEX; // nombre exacto del GSI
const JWT_SECRET = process.env.JWT_SECRET;

function json(statusCode, body) {
  return {
    statusCode,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  };
}

async function signGet(key) {
  if (!S3_BUCKET || !key) return null;
  return await getSignedUrl(
    s3,
    new GetObjectCommand({ Bucket: S3_BUCKET, Key: key }),
    { expiresIn: SIGNED_URL_TTL_SECONDS }
  );
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

// helper: chunk array (BatchGet max 100 keys)
function chunk(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

export const handler = async (event) => {
  if (event.requestContext?.http?.method === "OPTIONS") return json(200, { ok: true });

  try {
    if (!USER_TEAMS_INDEX) return json(500, { message: "Falta USER_TEAMS_INDEX en env vars" });
    if (!TEAMS_TABLE) return json(500, { message: "Falta TEAMS_TABLE en env vars" });
    if (!TEAM_MEMBERS_TABLE) return json(500, { message: "Falta TEAM_MEMBERS_TABLE en env vars" });

    const auth = requireAuth(event);

    // 1) memberships del usuario
    const memRes = await ddb.send(
      new QueryCommand({
        TableName: TEAM_MEMBERS_TABLE,
        IndexName: USER_TEAMS_INDEX,
        KeyConditionExpression: "#u = :uid",
        ExpressionAttributeNames: { "#u": "userId" },
        ExpressionAttributeValues: { ":uid": auth.sub },
      })
    );

    // más estricto: solo activos
    const membershipsRaw = memRes.Items || [];
    const memberships = membershipsRaw.filter((m) => (m.status ?? "ACTIVE") === "ACTIVE");

    if (memberships.length === 0) {
      return json(200, { message: "OK", ownedTeams: [], memberTeams: [] });
    }

    // 2) dedup teamIds (por si hay registros duplicados)
    const uniqueTeamIds = [...new Set(memberships.map((m) => m.teamId))];

    // 3) BatchGet teams (chunk de 100)
    const teamItems = [];
    for (const batchIds of chunk(uniqueTeamIds, 100)) {
      const batchRes = await ddb.send(
        new BatchGetCommand({
          RequestItems: {
            [TEAMS_TABLE]: {
              Keys: batchIds.map((teamId) => ({ teamId })),
              // traemos solo lo necesario (evita payload gigante)
              ProjectionExpression: "teamId, teamName, country, province, ownerUserId, logoKey",
            },
          },
        })
      );

      teamItems.push(...(batchRes.Responses?.[TEAMS_TABLE] || []));
      // si hubiera UnprocessedKeys podríamos reintentar, pero para tu escala hoy no hace falta
    }

    const teamById = new Map(teamItems.map((t) => [t.teamId, t]));

    // 4) Armar DTOs (firmas en paralelo)
    const ownedTeams = [];
    const memberTeams = [];

    const dtos = await Promise.all(
      memberships.map(async (m) => {
        const team = teamById.get(m.teamId);
        if (!team) return null;

        const logoUrl = team.logoKey ? await signGet(team.logoKey) : null;

        return {
          teamId: team.teamId,
          teamName: team.teamName ?? null,
          country: team.country ?? null,
          province: team.province ?? null,
          ownerUserId: team.ownerUserId ?? null,
          accessRole: m.accessRole ?? "MEMBER", // OWNER / MEMBER
          teamRole: m.teamRole ?? "PLAYER",     // PLAYER / STAFF
          joinedAt: m.joinedAt ?? null,
          logoUrl,
        };
      })
    );

    for (const dto of dtos) {
      if (!dto) continue;
      if (dto.accessRole === "OWNER") ownedTeams.push(dto);
      else memberTeams.push(dto);
    }

    // 5) opcional: ordenar por nombre (teamName)
    ownedTeams.sort((a, b) => String(a.teamName || "").localeCompare(String(b.teamName || "")));
    memberTeams.sort((a, b) => String(a.teamName || "").localeCompare(String(b.teamName || "")));

    return json(200, { message: "OK", ownedTeams, memberTeams });
  } catch (err) {
    console.error(err);
    return json(err.statusCode || 500, { message: err.message || "Error interno" });
  }
};
