import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, QueryCommand, BatchGetCommand } from "@aws-sdk/lib-dynamodb";
import jwt from "jsonwebtoken";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const TEAMS_TABLE = process.env.TEAMS_TABLE;
const TEAM_MEMBERS_TABLE = process.env.TEAM_MEMBERS_TABLE;
const USER_TEAMS_INDEX = process.env.USER_TEAMS_INDEX; // nombre exacto del GSI
const JWT_SECRET = process.env.JWT_SECRET;

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

export const handler = async (event) => {
  if (event.requestContext?.http?.method === "OPTIONS") return json(200, { ok: true });

  try {
    if (!USER_TEAMS_INDEX) return json(500, { message: "Falta USER_TEAMS_INDEX en env vars" });

    const auth = requireAuth(event);

    // 1) Traer memberships del usuario
    const memRes = await ddb.send(
      new QueryCommand({
        TableName: TEAM_MEMBERS_TABLE,
        IndexName: USER_TEAMS_INDEX,
        KeyConditionExpression: "#u = :uid",
        ExpressionAttributeNames: { "#u": "userId" },
        ExpressionAttributeValues: { ":uid": auth.sub },
      })
    );

    const memberships = (memRes.Items || [])
      .filter((m) => m.status !== "REMOVED"); // por si usás soft-delete

    if (memberships.length === 0) {
      return json(200, { message: "OK", ownedTeams: [], memberTeams: [] });
    }

    // 2) BatchGet de teams (más eficiente que Get uno por uno)
    const keys = memberships.map((m) => ({ teamId: m.teamId }));

    // Dynamo BatchGet tiene limite 100 keys, por ahora ok.
    const batchRes = await ddb.send(
      new BatchGetCommand({
        RequestItems: {
          [TEAMS_TABLE]: {
            Keys: keys,
          },
        },
      })
    );

    const teams = batchRes.Responses?.[TEAMS_TABLE] || [];
    const teamById = new Map(teams.map((t) => [t.teamId, t]));

    // 3) Armar respuesta separada
    const ownedTeams = [];
    const memberTeams = [];

    for (const m of memberships) {
      const team = teamById.get(m.teamId);
      if (!team) continue;

      const dto = {
        teamId: team.teamId,
        teamName: team.teamName,
        country: team.country ?? null,
        province: team.province ?? null,
        ownerUserId: team.ownerUserId,
        accessRole: m.accessRole, // OWNER / MEMBER
        teamRole: m.teamRole,     // PLAYER / STAFF
        joinedAt: m.joinedAt ?? null,
      };

      if (m.accessRole === "OWNER") ownedTeams.push(dto);
      else memberTeams.push(dto);

    }

    return json(200, { message: "OK", ownedTeams, memberTeams });
  } catch (err) {
    console.error(err);
    return json(err.statusCode || 500, { message: err.message || "Error interno" });
  }
};
