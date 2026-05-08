const jwt = require("jsonwebtoken");

const ACCESS_TOKEN_TTL = process.env.AUTH_ACCESS_TOKEN_TTL || "7d";
const JWT_SECRET = process.env.AUTH_JWT_SECRET || process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.trim().length < 32) {
  throw new Error(
    "Missing or weak JWT secret. Set AUTH_JWT_SECRET (or JWT_SECRET) with at least 32 characters.",
  );
}

function issueAccessToken({ user, device }) {
  return jwt.sign(
    {
      sub: String(user._id),
      chatId: String(user.chatId),
      deviceId: String(device.deviceId),
      deviceType: String(device.type),
      platform: String(device.platform || "unknown"),
      tokenVersion: Number(device.tokenVersion || 1),
    },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_TTL },
  );
}

function verifyAccessToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

function verifyAccessTokenAllowExpired(token) {
  return jwt.verify(token, JWT_SECRET, { ignoreExpiration: true });
}

function isTokenExpiredError(error) {
  return Boolean(error && error.name === "TokenExpiredError");
}

module.exports = {
  issueAccessToken,
  verifyAccessToken,
  verifyAccessTokenAllowExpired,
  isTokenExpiredError,
};
