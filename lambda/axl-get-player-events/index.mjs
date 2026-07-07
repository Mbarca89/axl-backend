import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  QueryCommand,
} from "@aws-sdk/lib-dynamodb";
import jwt from "jsonwebtoken";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const PLAYER_EVENT_PARTICIPATION_TABLE =
  process.env.PLAYER_EVENT_PARTICIPATION_TABLE || "PlayerEventParticipation";
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

async function getPlayerEventHistory(userId) {
  const items = [];
  let lastKey;

  do {
    const res = await ddb.send(
      new QueryCommand({
        TableName: PLAYER_EVENT_PARTICIPATION_TABLE,
        KeyConditionExpression: "userId = :userId AND begins_with(sk, :sk)",
        ExpressionAttributeValues: {
          ":userId": userId,
          ":sk": "EVENT#",
        },
        ExclusiveStartKey: lastKey,
      })
    );

    items.push(...(res.Items || []));
    lastKey = res.LastEvaluatedKey;
  } while (lastKey);

  return items;
}

export const handler = async (event) => {
  const method = event.requestContext?.http?.method || event.httpMethod || "";

  if (method === "OPTIONS") {
    return json(200, { ok: true });
  }

  if (method !== "GET") {
    return json(405, { message: "Method not allowed" });
  }

  try {
    const auth = requireAuth(event);

    const items = await getPlayerEventHistory(auth.sub);

    const history = items
      .map((item) => ({
        eventId: item.eventId,
        teamId: item.teamId,
        rosterName: item.rosterName || null,
        category: item.category || null,
        status: item.status || null,

        finalRank: item.finalRank ?? null,
        teamPointsEarned: item.teamPointsEarned ?? null,
        totalTeams: item.totalTeams ?? null,

        teamRoleSnapshot: item.teamRoleSnapshot || null,
        countsForPoints: item.countsForPoints ?? null,

        createdAt: item.createdAt || null,
        updatedAt: item.updatedAt || null,
      }))
      .sort((a, b) => {
        const da = new Date(b.createdAt || 0).getTime();
        const db = new Date(a.createdAt || 0).getTime();
        return da - db;
      });

    return json(200, {
      userId: auth.sub,
      total: history.length,
      history,
    });
  } catch (err) {
    console.error("ERROR get-player-event-history", err);
    return json(err.statusCode || 500, {
      message: err.message || "Error interno",
    });
  }
};