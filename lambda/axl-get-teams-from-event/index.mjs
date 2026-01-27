import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const EVENT_REGISTRATIONS_TABLE = process.env.EVENT_REGISTRATIONS_TABLE;

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
    const qs = event.queryStringParameters || {};
    const eventId = String(qs.eventId || "").trim();
    if (!eventId) return json(400, { message: "Falta eventId (querystring)" });

    // categorías fijas del sistema (las tuyas)
    const CAT_5V5 = "5v5 D3/D4";
    const CAT_3V3_D5 = "3v3 D4/D5";
    const CAT_3V3_D6 = "3v3 D6";

    const buckets = {
      [CAT_5V5]: [],
      [CAT_3V3_D5]: [],
      [CAT_3V3_D6]: [],
    };

    const res = await ddb.send(
      new QueryCommand({
        TableName: EVENT_REGISTRATIONS_TABLE,
        KeyConditionExpression: "#pk = :eventId",
        ExpressionAttributeNames: { "#pk": "eventId" },
        ExpressionAttributeValues: { ":eventId": eventId },
        // si algún día hay >1MB, ahí sí habría que paginar, pero para AXL no pasa
      })
    );

    const items = res.Items ?? [];

    for (const it of items) {
      const row = {
        teamId: it.teamId,
        teamNameSnapshot: it.teamNameSnapshot,
        category: it.category,
        status: it.status,
        registeredAt: it.registeredAt,
        updatedAt: it.updatedAt,
      };

      if (buckets[it.category]) {
        buckets[it.category].push(row);
      } else {
        // por si aparece una categoría inesperada, no la perdemos
        if (!buckets.__OTHER__) buckets.__OTHER__ = [];
        buckets.__OTHER__.push(row);
      }
    }

    return json(200, {
      eventId,
      counts: Object.fromEntries(
        Object.entries(buckets).map(([k, arr]) => [k, arr.length])
      ),
      registrationsByCategory: buckets,
    });
  } catch (err) {
    console.error(err);
    return json(500, { message: "Error interno" });
  }
};
