const expressService = require("express");
const passwordHasher = require("bcrypt");
const tokenManager = require("jsonwebtoken");
const cryptoModule = require("crypto");
const pathResolver = require("path");
const { PrismaClient } = require("@prisma/client");
const authenticateToken = require("./middleware/auth");

const application = expressService();
const dbClient = new PrismaClient();

application.use(expressService.json());
application.use(expressService.static(pathResolver.join(__dirname, "../public")));

application.post("/signup", async (req, res) => {
  const { email: userEmail, password: userPassword, name: userName } = req.body;

  if (typeof userEmail !== "string" || typeof userPassword !== "string") {
    return res.status(400).json({ error: "Email and password must be strings" });
  }

  if (userPassword.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }

  const sanitizedEmail = userEmail.trim().toLowerCase();

  const accountFound = await dbClient.user.findUnique({
    where: { email: sanitizedEmail },
  });

  if (accountFound) {
    return res.status(409).json({ error: "Email already in use" });
  }

  const securePassword = await passwordHasher.hash(userPassword, 10);

  const newAccount = await dbClient.user.create({
    data: {
      email: sanitizedEmail,
      password: securePassword,
      name: userName || null,
    },
  });

  const tokenIdentifier = cryptoModule.randomUUID();

  const generatedToken = tokenManager.sign(
    { id: newAccount.id, email: newAccount.email, jti: tokenIdentifier },
    process.env.JWTSECRET,
    { expiresIn: "1h" }
  );

  return res.status(201).json({
    user: {
      id: newAccount.id,
      email: newAccount.email,
      name: newAccount.name,
      createdAt: newAccount.createdAt,
    },
    token: generatedToken,
  });
});

application.post("/login", async (req, res) => {
  const { email: loginEmail, password: loginPassword } = req.body;

  if (typeof loginEmail !== "string" || typeof loginPassword !== "string") {
    return res.status(400).json({ error: "Email and password must be strings" });
  }

  const sanitizedEmail = loginEmail.trim().toLowerCase();

  const matchedUser = await dbClient.user.findUnique({
    where: { email: sanitizedEmail },
  });

  if (!matchedUser) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  const isPasswordValid = await passwordHasher.compare(loginPassword, matchedUser.password);

  if (!isPasswordValid) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  const sessionTokenId = cryptoModule.randomUUID();

  const sessionToken = tokenManager.sign(
    { id: matchedUser.id, email: matchedUser.email, jti: sessionTokenId },
    process.env.JWTSECRET,
    { expiresIn: "1h" }
  );

  return res.status(200).json({
    user: {
      id: matchedUser.id,
      email: matchedUser.email,
      name: matchedUser.name,
      createdAt: matchedUser.createdAt,
    },
    token: sessionToken,
  });
});

application.get("/me", authenticateToken, async (req, res) => {
  const currentUser = await dbClient.user.findUnique({
    where: { id: req.user.id },
  });

  if (!currentUser) {
    return res.status(404).json({ error: "User not found" });
  }

  return res.status(200).json({
    id: currentUser.id,
    email: currentUser.email,
    name: currentUser.name,
    createdAt: currentUser.createdAt,
  });
});

application.get("/dashboard", authenticateToken, async (req, res) => {
  const userProfile = await dbClient.user.findUnique({
    where: { id: req.user.id },
  });

  if (!userProfile) {
    return res.status(404).json({ error: "User not found" });
  }

  const greetingName = userProfile.name || userProfile.email;

  return res.status(200).json({
    message: `Welcome, ${greetingName}!`,
    user: {
      id: userProfile.id,
      email: userProfile.email,
      name: userProfile.name,
      createdAt: userProfile.createdAt,
    },
  });
});

const APP_PORT = process.env.PORT || 3000;
application.listen(APP_PORT, () => {
  console.log(`Server running on port ${APP_PORT}`);
});
