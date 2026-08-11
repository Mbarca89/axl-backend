import test from "node:test";
import assert from "node:assert/strict";
import { resolveTargetUserId } from "./index.mjs";

test("uses the requested userId when present", () => {
  const event = {
    queryStringParameters: { userId: "target-user-123" },
    headers: { authorization: "Bearer demo-token" },
  };

  assert.equal(resolveTargetUserId(event, "auth-user-456"), "target-user-123");
});

test("falls back to the authenticated user when no target userId is provided", () => {
  const event = {
    headers: { authorization: "Bearer demo-token" },
  };

  assert.equal(resolveTargetUserId(event, "auth-user-456"), "auth-user-456");
});
