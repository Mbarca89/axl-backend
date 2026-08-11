import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, ScanCommand } from "@aws-sdk/lib-dynamodb";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const EVENT_TEAM_POINTS_TABLE =
  process.env.EVENT_TEAM_POINTS_TABLE || "EventTeamPoints";
const EXCLUDED_CATEGORIES = new Set(["3v3 Open"]);

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  };
}

async function scanAllTeamPoints() {
  const items = [];
  let lastKey;

  do {
    const res = await ddb.send(
      new ScanCommand({
        TableName: EVENT_TEAM_POINTS_TABLE,
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
    const qs = event.queryStringParameters || {};
    const categoryFilter = String(qs.category || "").trim();
    const yearFilter = String(qs.year || "").trim();

    const items = await scanAllTeamPoints();

    let rows = items.map((item) => ({
      eventId: item.eventId,
      year: item.year,
      teamId: item.teamId,
      teamName: item.teamName || null,
      category: item.category || null,
      finalRank: item.finalRank ?? null,
      totalTeams: item.totalTeams ?? null,
      points: item.points ?? null,
      calculationVersion: item.calculationVersion || null,
      closedAt: item.closedAt || null,
      closedBy: item.closedBy || null,
    })).filter((row) => !EXCLUDED_CATEGORIES.has(row.category));

    if (categoryFilter) {
      rows = rows.filter((r) => r.category === categoryFilter);
    }

    if (yearFilter) {
      rows = rows.filter((r) => {
        if (!r.closedAt) return false;
        return String(new Date(r.closedAt).getUTCFullYear()) === yearFilter;
      });
    }

    rows.sort((a, b) => {
      const da = new Date(b.closedAt || 0).getTime();
      const db = new Date(a.closedAt || 0).getTime();
      if (da !== db) return da - db;

      if ((b.points ?? -999999) !== (a.points ?? -999999)) {
        return (b.points ?? -999999) - (a.points ?? -999999);
      }

      return String(a.teamName || "").localeCompare(String(b.teamName || ""));
    });

    return json(200, {
      total: rows.length,
      items: rows,
    });
  } catch (err) {
    console.error("ERROR get-team-points-history", err);
    return json(500, {
      message: err.message || "Error interno",
    });
  }
};
