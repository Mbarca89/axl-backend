import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  QueryCommand,
  BatchGetCommand,
} from "@aws-sdk/lib-dynamodb";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const MATCHES_TABLE = process.env.MATCHES_TABLE || "Matches";
const TEAMS_TABLE = process.env.TEAMS_TABLE || "Teams";

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  };
}

async function getMatchesByEvent(eventId) {
  const res = await ddb.send(
    new QueryCommand({
      TableName: MATCHES_TABLE,
      KeyConditionExpression: "#pk = :e AND begins_with(#sk, :m)",
      ExpressionAttributeNames: {
        "#pk": "eventId",
        "#sk": "sk",
      },
      ExpressionAttributeValues: {
        ":e": eventId,
        ":m": "MATCH#",
      },
    })
  );

  return res.Items ?? [];
}

async function getTeams(teamIds) {
  if (!teamIds.length) return [];

  const keys = teamIds.map((teamId) => ({ teamId }));

  const res = await ddb.send(
    new BatchGetCommand({
      RequestItems: {
        [TEAMS_TABLE]: {
          Keys: keys,
        },
      },
    })
  );

  return res.Responses?.[TEAMS_TABLE] ?? [];
}

export const handler = async (event) => {
  const method = event.requestContext?.http?.method || event.httpMethod || "";

  if (method === "OPTIONS") return json(200, { ok: true });
  if (method !== "POST") return json(405, { message: "Method not allowed" });

  try {
    const body = event.body ? JSON.parse(event.body) : {};

    const eventId = String(body.eventId || "").trim();
    const teamIds = Array.isArray(body.teamIds)
      ? body.teamIds.map((x) => String(x).trim()).filter(Boolean)
      : [];

    if (!eventId) return json(400, { message: "Falta eventId" });
    if (!teamIds.length) return json(400, { message: "Falta teamIds" });

    const [matches, teams] = await Promise.all([
      getMatchesByEvent(eventId),
      getTeams(teamIds),
    ]);

    const teamMap = new Map(
      teams.map((t) => [
        t.teamId,
        {
          teamId: t.teamId,
          teamName: t.teamName || t.name || null,
        },
      ])
    );

    const resultMap = new Map();

    for (const teamId of teamIds) {
      resultMap.set(teamId, {
        teamId,
        teamName: teamMap.get(teamId)?.teamName ?? null,
        matches: [],
      });
    }

    for (const m of matches) {
      for (const teamId of teamIds) {
        if (m.leftTeamId === teamId || m.rightTeamId === teamId) {
          resultMap.get(teamId).matches.push({
            matchId: m.matchId,
            category: m.category,
            day: m.day,
            stage: m.stage,
            slot: m.slot,
            displayLabel: m.displayLabel,
            leftTeamId: m.leftTeamId,
            leftTeamNameSnapshot: m.leftTeamNameSnapshot,
            rightTeamId: m.rightTeamId,
            rightTeamNameSnapshot: m.rightTeamNameSnapshot,
            leftScore: m.leftScore,
            rightScore: m.rightScore,
            timeRemainingSec: m.timeRemainingSec,
            notes: m.notes,
            isFinished: m.isFinished,
            resultType: m.resultType,
            winnerTeamId: m.winnerTeamId,
          });
        }
      }
    }

    const teamsWithMatches = [...resultMap.values()].map((team) => {
      team.matches.sort((a, b) => {
        if ((a.day ?? 99) !== (b.day ?? 99)) return (a.day ?? 99) - (b.day ?? 99);
        const aLabel = String(a.displayLabel || "");
        const bLabel = String(b.displayLabel || "");
        return aLabel.localeCompare(bLabel);
      });
      return team;
    });

    return json(200, {
      eventId,
      teams: teamsWithMatches,
    });
  } catch (err) {
    console.error(err);
    return json(500, { message: "Error interno" });
  }
};