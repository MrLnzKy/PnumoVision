const express = require("express");
const bcrypt = require("bcrypt");
const mysql = require("mysql2");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
  host: "34.101.242.156",
  user: "root",
  password: "X^Q+GN%n@C=c%3}c",
  database: "UserAccount",
});

const jwtSecret = "2lmBFtAY0HybUp1L74qGTerX1YgIgNHn";
const PORT = process.env.PORT || 8080;

app.get("/", (req, res) => {
  res.send("Welcome to the API!");
});

const generateToken = (userId) => {
  return jwt.sign({ id: userId }, jwtSecret, { expiresIn: "24h" });
};

// Middleware to authenticate and verify token
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res
      .status(403)
      .json({ error: "A token is required for authentication" });
  }

  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded;
  } catch (err) {
    return res.status(401).json({ error: "Invalid Token" });
  }

  next();
};

// Endpoint for registration
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const emailCheckSql = "SELECT email FROM users WHERE email = ?";
    db.query(emailCheckSql, [email], async (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (results.length > 0) {
        return res.status(409).json({ error: "Email already in use" }); // Menggunakan status 409 untuk conflict
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const insertSql =
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
      db.query(insertSql, [name, email, hashedPassword], (err, results) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }

        res.status(201).json({ message: "User registered" }); // Removed the token generation
      });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Endpoint for login
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (results.length === 0) {
        return res.status(401).json({ error: "User not found" });
      }

      const user = results[0];
      if (await bcrypt.compare(password, user.password)) {
        const token = generateToken(user.id); // Generate token
        res.status(200).json({ message: "Login successful", token });
      } else {
        res.status(401).json({ error: "Invalid password" });
      }
    }
  );
});

// Endpoint for retrieving registered users
// Endpoint for retrieving all registered users with their details
app.get("/users", authenticateToken, (req, res) => {
  db.query("SELECT name, email FROM users", (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(200).json(results);
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
