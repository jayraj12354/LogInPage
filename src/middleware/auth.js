const tokenHandler = require("jsonwebtoken");

function authenticateToken(req, res, next) {
  const authHeaderValue = req.headers.authorization;

  if (!authHeaderValue || !authHeaderValue.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided" });
  }

  const authToken = authHeaderValue.split(" ")[1];

  try {
    const payload = tokenHandler.verify(authToken, process.env.JWTSECRET);
    req.user = payload;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

module.exports = authenticateToken;
