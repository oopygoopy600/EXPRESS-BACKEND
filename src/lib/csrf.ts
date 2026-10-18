import { randomBytes } from "node:crypto";
import { doubleCsrf } from "csrf-csrf";
import { ENV } from "@/config/env";

const isProduction = ENV.NODE_ENV === "production";

export const csrfCookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? "none" as const : "lax" as const,
  path: "/",
};

export const csrfSessionCookieName = isProduction
  ? "__Host-csrf-session"
  : "csrf-session";

export const csrfTokenCookieName = isProduction
  ? "__Host-csrf-token"
  : "csrf-token";

const csrfSecret = ENV.CSRF_SECRET || randomBytes(32).toString("hex");

if (isProduction && !ENV.CSRF_SECRET) {
  throw new Error("CSRF_SECRET is required in production");
}

export const { generateCsrfToken, validateRequest } = doubleCsrf({
  getSecret: () => csrfSecret,

  // Use the same session identifier before and after authentication.
  getSessionIdentifier: (req) =>
    req.cookies?.[csrfSessionCookieName] || "",

  cookieName: csrfTokenCookieName,
  cookieOptions: csrfCookieOptions,
  getCsrfTokenFromRequest: (req) =>
    req.get("x-csrf-token"),
});
