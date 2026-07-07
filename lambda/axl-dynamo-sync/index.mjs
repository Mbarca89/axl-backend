import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  BatchWriteCommand,
} from "@aws-sdk/lib-dynamodb";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const SYNC_TOKEN = process.env.SYNC_TOKEN;

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  };
}

function chunkArray(arr, size = 25) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) {
    out.push(arr.slice(i, i + size));
  }
  return out;
}

async function batchWriteAll(tableName, items) {
  const chunks = chunkArray(items, 25);

  for (const chunk of chunks) {
    let requestItems = {
      [tableName]: chunk.map((item) => ({
        PutRequest: { Item: item },
      })),
    };

    let attempts = 0;

    while (Object.keys(requestItems).length > 0 && attempts < 5) {
      const res = await ddb.send(
        new BatchWriteCommand({
          RequestItems: requestItems,
        })
      );

      requestItems = res.UnprocessedItems || {};
      attempts++;

      if (Object.keys(requestItems).length > 0) {
        console.warn(`Retrying unprocessed items for ${tableName}, attempt ${attempts}`);
        await new Promise((resolve) => setTimeout(resolve, 200 * attempts));
      }
    }

    if (Object.keys(requestItems).length > 0) {
      throw new Error(`No se pudieron escribir todos los items en ${tableName}`);
    }
  }
}

export const handler = async (event) => {
  try {
    const token =
      event.headers?.["x-sync-token"] ||
      event.headers?.["X-Sync-Token"];

    if (!token || token !== SYNC_TOKEN) {
      return json(403, { message: "Forbidden" });
    }

    const body = event.body ? JSON.parse(event.body) : {};

    const {
      event_id,
      block_id = null,
      matches = [],
      fixtureBlocks = [],
      tables = {},
    } = body;

    if (!event_id) {
      return json(400, { message: "event_id requerido" });
    }

    const MATCHES_TABLE = tables.matches || "Matches";
    const BLOCKS_TABLE = tables.fixtureBlocks || "FixtureBlocks";

    console.log("Sync start:", {
      event_id,
      block_id,
      matches: matches.length,
      fixtureBlocks: fixtureBlocks.length,
    });

    const normalizedMatches = matches.map((m) => ({
      eventId: m.event_id ?? event_id,          // PK real Dynamo
      sk: m.sk ?? `MATCH#${m.match_id}`,
      matchId: m.match_id,
      blockId: m.block_id,
      blockSk: m.block_sk ?? `BLOCK#${m.block_id}`,
      category: m.category,
      createdAt: m.created_at,
      displayLabel: m.display_label,
      isFinished: m.is_finished,
      leftScore: m.left_score,
      leftTeamId: m.left_team_id,
      leftTeamLogoKey: m.left_team_logo_path,
      leftTeamNameSnapshot: m.left_team_name,
      notes: m.notes,
      resultType: m.result_type,
      rightScore: m.right_score,
      rightTeamId: m.right_team_id,
      rightTeamLogoKey: m.right_team_logo_path,
      rightTeamNameSnapshot: m.right_team_name,
      slot: m.slot,
      stage: m.stage,
      timeRemainingSec: m.time_remaining_sec,
      updatedAt: m.updated_at,
      winnerTeamId: m.winner_team_id,
    }));

    const normalizedBlocks = fixtureBlocks.map((b) => ({
      eventId: b.event_id ?? event_id,          // PK real Dynamo
      sk: b.sk ?? `BLOCK#${b.block_id}`,
      blockId: b.block_id,
      activeSlot: b.active_slot,
      blockOrder: b.block_order,
      category: b.category,
      createdAt: b.created_at,
      matchAId: b.match_a_id ?? null,
      matchBId: b.match_b_id ?? null,
      stage: b.stage,
      status: b.status,
      updatedAt: b.updated_at,
    }));

    if (normalizedMatches.length > 0) {
      await batchWriteAll(MATCHES_TABLE, normalizedMatches);
    }

    if (normalizedBlocks.length > 0) {
      await batchWriteAll(BLOCKS_TABLE, normalizedBlocks);
    }

    return json(200, {
      ok: true,
      scope: block_id ? "block" : "event",
      event_id,
      block_id,
      matches: normalizedMatches.length,
      fixtureBlocks: normalizedBlocks.length,
    });
  } catch (err) {
    console.error("SYNC ERROR", err);
    return json(500, {
      message: "Error interno",
      error: err.message,
    });
  }
};