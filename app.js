const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const cors = require('cors');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(express.json());

// CORS setup
app.use(cors({
    origin: 'http://localhost:5173', // Front-end application URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true // Allow cookies and credentials
  }));
  

// Session setup
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true if using HTTPS
}));

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// User model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

// Hash password before saving user
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// Compare password method
userSchema.methods.comparePassword = function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Middleware to check authentication
function isAuthenticated(req, res, next) {
  if (req.session.email || req.session.username) {
    return next();
  }
  res.status(401).json({ error: 'Unauthorized' });
}

// Register Route
app.post('/api/user/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const user = new User({ username, email, password });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Login Route
app.post('/api/user/login', async (req, res) => {
  const { email, username, password } = req.body;
  try {
    const user = await User.findOne({ $or: [{ email }, { username }] });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(400).json({ error: 'Invalid email/username or password' });
    }

    req.session.userId = user._id; // Save user ID in session
    req.session.email = user.email; // Save email in session
    req.session.username = user.username; // Save username in session

    res.json({ username: user.username, message: 'Login successful' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Logout Route
app.post('/api/user/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to logout' });
    }
    res.json({ message: 'Logout successful' });
  });
});

// Get Profile Route (find by email or username)
app.get('/api/user/profile', async (req, res) => {
    try {
      const { username } = req.query; // or use req.query.email if preferred
      if (!username) {
        return res.status(400).json({ error: 'Username or email is required' });
      }
  
      const user = await User.findOne({ username }).select('username email');
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
  
      // Mock profile data for demonstration
      const profile = {
        username: user.username,
        email: user.email,
        posts: [
          { id: 1, content: 'This is a post', createdAt: new Date().toISOString() },
          { id: 2, content: 'Another post', createdAt: new Date().toISOString() },
        ],
        followersCount: 123,
        followingCount: 456,
        friends: [
          { id: 1, name: 'Friend One', avatar: 'https://via.placeholder.com/60' },
          { id: 2, name: 'Friend Two', avatar: 'https://via.placeholder.com/60' },
        ],
      };
  
      res.json(profile);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
  

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
