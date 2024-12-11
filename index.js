// Import dependencies
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
const cors = require('cors');

// App setup
const app = express();
const PORT = 3000;
const JWT_SECRET = "ramdomharkiratilovekiara";

// Middleware
app.use(express.json());
app.use(cors());

// In-memory user store
const users = [];

// Serve static files
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Signup endpoint
app.post("/signup", async (req, res) => {
    const { username, password } = req.body;

    // Check if user already exists
    if (users.find(user => user.username === username)) {
        return res.status(400).json({ message: "User already exists" });
    }

    // Hash password and store user
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });

    res.json({ message: "You are signed up" });
});

// Signin endpoint
app.post("/signin", async (req, res) => {
    const { username, password } = req.body;

    const foundUser = users.find(user => user.username === username);
    if (foundUser && await bcrypt.compare(password, foundUser.password)) {
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
        return res.json({ token });
    }

    res.status(403).json({ message: "Invalid username or password" });
});

// Token verification middleware
function verifyToken(req, res, next) {
    const token = req.headers.token;
    if (!token) {
        return res.status(403).json({ message: "No token provided" });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: "Failed to authenticate token" });
        }
        req.username = decoded.username;
        next();
    });
}

// Protected route
app.get("/me", verifyToken, (req, res) => {
    const foundUser = users.find(user => user.username === req.username);

    if (foundUser) {
        res.json({ username: foundUser.username });
    } else {
        res.status(404).json({ message: "User not found" });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: "Something went wrong!" });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
