import jwt from "jsonwebtoken";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";

const s3 = new S3Client({});
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const S3_BUCKET = process.env.S3_BUCKET;
const TEAMS_TABLE = process.env.TEAMS_TABLE || "Teams";
const TEAM_MEMBERS_TABLE = process.env.TEAM_MEMBERS_TABLE || "TeamMembers";
const JWT_SECRET = process.env.JWT_SECRET;
const SIGNED_UPLOAD_TTL_SECONDS = Number(process.env.SIGNED_UPLOAD_TTL_SECONDS || "300");

function json(statusCode, body) {
    return {
        statusCode,
        headers: {
            "content-type": "application/json",
            "access-control-allow-origin": "*",
            "access-control-allow-methods": "OPTIONS,POST",
            "access-control-allow-headers": "content-type,authorization",
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

function extFromContentType(ct) {
    if (ct === "image/jpeg") return "jpg";
    if (ct === "image/png") return "png";
    return null;
}

export const handler = async (event) => {
    if (event.requestContext?.http?.method === "OPTIONS") return json(200, { ok: true });

    try {
        const auth = requireAuth(event);
        if (!S3_BUCKET) return json(500, { message: "Falta S3_BUCKET en env" });

        const body = event.body ? JSON.parse(event.body) : {};
        const teamId = String(body.teamId || "").trim();
        const contentType = String(body.contentType || "").trim().toLowerCase();

        if (!teamId) return json(400, { message: "Falta teamId" });

        const ext = extFromContentType(contentType);
        if (!ext) return json(400, { message: "contentType inválido (image/jpeg o image/png)" });

        // Team existe?
        const teamRes = await ddb.send(new GetCommand({ TableName: TEAMS_TABLE, Key: { teamId } }));
        if (!teamRes.Item) return json(404, { message: "Team no encontrado" });

        // Soy OWNER?
        const meRes = await ddb.send(
            new GetCommand({
                TableName: TEAM_MEMBERS_TABLE,
                Key: { teamId, sk: `USER#${auth.sub}` },
            })
        );

        const me = meRes.Item;
        if (!me || me.status !== "ACTIVE") return json(403, { message: "No sos miembro activo" });
        if (me.accessRole !== "OWNER") return json(403, { message: "Solo el OWNER puede subir logo" });

        const key = `teams/${teamId}/logo.${ext}`;
        const now = new Date().toISOString();

        const uploadUrl = await getSignedUrl(
            s3,
            new PutObjectCommand({
                Bucket: S3_BUCKET,
                Key: key,
                ContentType: contentType,
                Metadata: { teamId, uploadedBy: auth.sub },
            }),
            { expiresIn: SIGNED_UPLOAD_TTL_SECONDS }
        );

        // Guardar logoKey
        await ddb.send(
            new UpdateCommand({
                TableName: TEAMS_TABLE,
                Key: { teamId },
                UpdateExpression: "SET logoKey = :k, logoUpdatedAt = :t, updatedAt = :t",
                ExpressionAttributeValues: { ":k": key, ":t": now },
                ConditionExpression: "attribute_exists(teamId)",
            })
        );

        return json(200, { message: "OK", teamId, key, uploadUrl, expiresIn: SIGNED_UPLOAD_TTL_SECONDS });
    } catch (err) {
        console.error(err);

        if (err.name === "ConditionalCheckFailedException") {
            return json(404, { message: "Team no existe" });
        }

        return json(err.statusCode || 500, { message: err.message || "Error interno" });
    }
};
