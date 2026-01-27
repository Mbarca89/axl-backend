// create-event.mjs
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb";
import { randomUUID } from "crypto";
import fs from "fs";

function die(msg) {
    console.error(msg);
    process.exit(1);
}

function nowIso() {
    return new Date().toISOString();
}

function validateEvent(input) {
    const required = ["season", "name", "status", "categories", "registrationOpensAt", "registrationClosesAt"];
    for (const k of required) {
        if (input[k] === undefined || input[k] === null || input[k] === "") die(`Falta campo obligatorio: ${k}`);
    }

    if (!Array.isArray(input.categories) || input.categories.length === 0) {
        die("categories debe ser un array no vacío");
    }

    const allowedStatus = new Set([
        "DRAFT",
        "REGISTRATION_OPEN",
        "REGISTRATION_CLOSED",
        "FIXTURE_PUBLISHED",
        "IN_PROGRESS",
        "FINISHED",
    ]);
    if (!allowedStatus.has(input.status)) {
        die(`status inválido: ${input.status}`);
    }

    const open = new Date(input.registrationOpensAt);
    const close = new Date(input.registrationClosesAt);
    if (Number.isNaN(open.getTime())) die("registrationOpensAt no es una fecha válida");
    if (Number.isNaN(close.getTime())) die("registrationClosesAt no es una fecha válida");
    if (open.getTime() > close.getTime()) die("registrationOpensAt no puede ser posterior a registrationClosesAt");
}

function readJsonFile(path) {
    const raw = fs.readFileSync(path, "utf8");
    const cleaned = raw.replace(/^\uFEFF/, "").trim(); // quita BOM
    return JSON.parse(cleaned);
}

async function main() {
    const tableName = "Events";

    // Uso:
    // node create-event.mjs --file .\event.json
    const args = process.argv.slice(2);
    const fileIdx = args.indexOf("--file");

    let input;

    try {
        if (fileIdx !== -1) {
            const filePath = args[fileIdx + 1];
            if (!filePath) die("Falta ruta de archivo. Uso: node create-event.mjs --file .\\event.json");
            input = readJsonFile(filePath);
        } else {
            // fallback: JSON directo (solo si querés)
            const arg = args[0];
            if (!arg) die("Uso: node create-event.mjs --file .\\event.json");
            const cleaned = String(arg).replace(/^\uFEFF/, "").trim();
            input = JSON.parse(cleaned);
        }
    } catch (e) {
        console.error("Error parseando JSON:", e?.message || e);
        die("El JSON no es válido");
    }

    validateEvent(input);

    const ddb = DynamoDBDocumentClient.from(
        new DynamoDBClient({ region: "sa-east-1" })
    );
    const eventId = input.eventId?.trim() || randomUUID();
    const createdAt = input.createdAt || nowIso();
    const updatedAt = input.updatedAt || createdAt;

    const item = {
        eventId,
        season: Number(input.season),
        name: String(input.name),
        location: input.location ?? null,
        status: String(input.status),
        categories: input.categories.map(String),
        registrationOpensAt: String(input.registrationOpensAt),
        registrationClosesAt: String(input.registrationClosesAt),
        maxTeams: input.maxTeams ?? null,
        fixtureVersion: input.fixtureVersion ?? 0,
        frozenAt: input.frozenAt ?? null,
        createdAt,
        updatedAt,
    };

    await ddb.send(
        new PutCommand({
            TableName: tableName,
            Item: item,
            ConditionExpression: "attribute_not_exists(eventId)",
        })
    );

    console.log("Evento creado OK:");
    console.log(JSON.stringify(item, null, 2));
}

main().catch((e) => {
    console.error("Error:", e?.name || e, e?.message || "");
    process.exit(1);
});
