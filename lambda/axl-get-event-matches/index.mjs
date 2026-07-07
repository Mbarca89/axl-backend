import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  QueryCommand,
} from "@aws-sdk/lib-dynamodb";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const MATCHES_TABLE = process.env.MATCHES_TABLE || "Matches";
const FIXTURE_BLOCKS_TABLE = process.env.FIXTURE_BLOCKS_TABLE || "FixtureBlocks";

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "access-control-allow-headers": "content-type",
    },
    body: JSON.stringify(body),
  };
}

async function getMatchesByEvent(eventId) {
  const res = await ddb.send(
    new QueryCommand({
      TableName: MATCHES_TABLE,
      KeyConditionExpression: "#pk = :eventId AND begins_with(#sk, :matchPrefix)",
      ExpressionAttributeNames: {
        "#pk": "eventId",
        "#sk": "sk",
      },
      ExpressionAttributeValues: {
        ":eventId": eventId,
        ":matchPrefix": "MATCH#",
      },
    })
  );

  return res.Items ?? [];
}

async function getBlocksByEvent(eventId) {
  const res = await ddb.send(
    new QueryCommand({
      TableName: FIXTURE_BLOCKS_TABLE,
      KeyConditionExpression: "#pk = :eventId AND begins_with(#sk, :blockPrefix)",
      ExpressionAttributeNames: {
        "#pk": "eventId",
        "#sk": "sk",
      },
      ExpressionAttributeValues: {
        ":eventId": eventId,
        ":blockPrefix": "BLOCK#",
      },
    })
  );

  return res.Items ?? [];
}

function normalizeMatch(m) {
  return {
    block_id:
      m.blockId ??
      (typeof m.blockSk === "string" && m.blockSk.startsWith("BLOCK#")
        ? m.blockSk.slice("BLOCK#".length)
        : null),

    category: m.category ?? null,
    group_id: m.groupId ?? null,

    left_team_id: m.leftTeamId ?? null,
    left_team_name: m.leftTeamNameSnapshot ?? null,
    right_team_id: m.rightTeamId ?? null,
    right_team_name: m.rightTeamNameSnapshot ?? null,

    left_score: m.leftScore ?? 0,
    right_score: m.rightScore ?? 0,

    is_finished: Boolean(m.isFinished),
    finished_at: m.finishedAt ?? null,
    winner_team_id: m.winnerTeamId ?? null,
    result_type: m.resultType ?? null,

    stage: m.stage ?? null,
  };
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
    const eventId = String(event.queryStringParameters?.eventId || "").trim();

    if (!eventId) {
      return json(400, { message: "Falta eventId" });
    }

    const [matchesRaw, blocks] = await Promise.all([
      getMatchesByEvent(eventId),
      getBlocksByEvent(eventId),
    ]);

    const groupByBlockId = {};
    for (const b of blocks) {
      const blockId =
        b.blockId ||
        (typeof b.sk === "string" && b.sk.startsWith("BLOCK#")
          ? b.sk.slice("BLOCK#".length)
          : b.sk);

      groupByBlockId[blockId] = b.activeSlot ?? "A";
    }

    const matches = matchesRaw.map(normalizeMatch);

    return json(200, {
      eventId,
      matches,
      groupByBlockId,
    });
  } catch (err) {
    console.error(err);
    return json(500, { message: err.message || "Error interno" });
  }
};