import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, ScanCommand } from "@aws-sdk/lib-dynamodb";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const EVENTS_TABLE = process.env.EVENTS_TABLE;

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
  const method = event.requestContext?.http?.method || event.httpMethod || "";

  if (method === "OPTIONS") return json(200, { ok: true });
  if (method !== "GET") return json(405, { message: "Method not allowed" });

  try {
    const res = await ddb.send(
      new ScanCommand({
        TableName: EVENTS_TABLE,
        FilterExpression: "#st = :open",
        ExpressionAttributeNames: { "#st": "status" },
        ExpressionAttributeValues: { ":open": "REGISTRATION_OPEN" },
        Limit: 10,
      })
    );

    const items = res.Items ?? [];

    if (items.length === 0) {
      return json(200, { open: false, event: null });
    }

    // Si por error hay más de uno abierto, elegimos el más nuevo por registrationOpensAt (o createdAt)
    items.sort((a, b) => {
      const da = new Date(a.registrationOpensAt || a.createdAt || 0).getTime();
      const db = new Date(b.registrationOpensAt || b.createdAt || 0).getTime();
      return db - da;
    });

    const ev = items[0];

    return json(200, {
      open: true,
      event: {
        eventId: ev.eventId,
        season: ev.season,
        name: ev.name,
        location: ev.location ?? null,
        status: ev.status,
        categories: ev.categories ?? [],
        registrationOpensAt: ev.registrationOpensAt,
        registrationClosesAt: ev.registrationClosesAt,
      },
    });
  } catch (err) {
    console.error(err);
    return json(500, { message: "Error interno" });
  }
};
