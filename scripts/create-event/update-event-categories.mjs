import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import fs from "fs";

function die(message) {
    console.error(message);
    process.exit(1);
}

function readJsonFile(path) {
    const raw = fs.readFileSync(path, "utf8");
    return JSON.parse(raw.replace(/^\uFEFF/, "").trim());
}

async function main() {
    const args = process.argv.slice(2);
    const fileIndex = args.indexOf("--file");
    const filePath = fileIndex === -1 ? null : args[fileIndex + 1];

    if (!filePath) {
        die("Uso: node update-event-categories.mjs --file .\\event-fecha-2.json");
    }

    const input = readJsonFile(filePath);
    const eventId = String(input.eventId || "").trim();
    const categories = Array.isArray(input.categories)
        ? [...new Set(input.categories.map((category) => String(category).trim()).filter(Boolean))]
        : [];

    if (!eventId) die("Falta eventId");
    if (categories.length === 0) die("categories debe ser un array no vacío");

    const ddb = DynamoDBDocumentClient.from(
        new DynamoDBClient({ region: "sa-east-1" })
    );
    const updatedAt = new Date().toISOString();

    const result = await ddb.send(new UpdateCommand({
        TableName: "Events",
        Key: { eventId },
        ConditionExpression: "attribute_exists(eventId)",
        UpdateExpression: "SET categories = :categories, updatedAt = :updatedAt",
        ExpressionAttributeValues: {
            ":categories": categories,
            ":updatedAt": updatedAt,
        },
        ReturnValues: "ALL_NEW",
    }));

    console.log("Categorías actualizadas OK:");
    console.log(JSON.stringify(result.Attributes, null, 2));
}

main().catch((error) => {
    console.error("Error:", error?.name || error, error?.message || "");
    process.exit(1);
});
