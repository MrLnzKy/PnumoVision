const express = require("express");
const bcrypt = require("bcrypt");
const mysql = require("mysql2");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bodyParser = require("body-parser");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors());
app.use(bodyParser.text());

const db = mysql.createConnection({
  host: "34.101.242.156",
  user: "root",
  password: "X^Q+GN%n@C=c%3}c",
  database: "UserAccount",
});

const jwtSecret = "2lmBFtAY0HybUp1L74qGTerX1YgIgNHn";
const PORT = process.env.PORT || 8080;

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, "uploads");
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({ storage });

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

    // Check if the token is blacklisted
    db.query(
      "SELECT token FROM blacklist WHERE token = ?",
      [token],
      (err, results) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }

        if (results.length > 0) {
          return res.status(401).json({ error: "Token is blacklisted" });
        }

        next();
      }
    );
  } catch (err) {
    return res.status(401).json({ error: "Invalid Token" });
  }
};

// Endpoint for registration
app.post("/register", upload.single("profile_picture"), async (req, res) => {
  const { name, email, password } = req.body;
  const profilePicture = req.file ? req.file.path : null;

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
        return res.status(409).json({ error: "Email already in use" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const insertSql =
        "INSERT INTO users (name, email, password, profile_picture) VALUES (?, ?, ?, ?)";
      db.query(
        insertSql,
        [name, email, hashedPassword, profilePicture],
        (err, results) => {
          if (err) {
            return res.status(500).json({ error: err.message });
          }

          res.status(201).json({ message: "User registered" });
        }
      );
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
app.get("/users", authenticateToken, (req, res) => {
  db.query("SELECT name, email, profile_picture FROM users", (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(200).json(results);
  });
});

//Endpoint for LogOut
app.post("/logout", authenticateToken, (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  db.query(
    "INSERT INTO blacklist (token) VALUES (?)",
    [token],
    (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      res.status(200).json({ message: "Logout successful" });
    }
  );
});

//Endpoint for profile
app.get("/profile", authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.query(
    "SELECT name, email, profile_picture FROM users WHERE id = ?",
    [userId],
    (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (results.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      const user = results[0];
      res.status(200).json(user);
    }
  );
});

// Endpoint for updating user profile
app.put(
  "/profile",
  authenticateToken,
  upload.single("profile_picture"),
  (req, res) => {
    const userId = req.user.id;
    const { name } = req.body;
    const profilePicture = req.file ? req.file.path : null;

    let updateSql = "UPDATE users SET ";
    const updateFields = [];
    const updateValues = [];

    if (name) {
      updateFields.push("name = ?");
      updateValues.push(name);
    }

    if (profilePicture) {
      updateFields.push("profile_picture = ?");
      updateValues.push(profilePicture);
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ error: "No fields to update" });
    }

    updateSql += updateFields.join(", ") + " WHERE id = ?";
    updateValues.push(userId);

    db.query(updateSql, updateValues, (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      res.status(200).json({ message: "Profile updated successfully" });
    });
  }
);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
