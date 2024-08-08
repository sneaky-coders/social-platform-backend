const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'uploads'))); // Serve static files from uploads directory

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

userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

userSchema.methods.comparePassword = function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Post model
// Post model
const postSchema = new mongoose.Schema({
  content: { type: String, required: true },
  image: { type: String }, // Path to the uploaded image
  username: { type: String }, // Store username instead of userId
  createdAt: { type: Date, default: Date.now },
  likesCount: { type: Number, default: 0 }, // Added likes count
});




const Post = mongoose.model('Post', postSchema);

// Like model
const likeSchema = new mongoose.Schema({
  postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
});

const Like = mongoose.model('Like', likeSchema);

// Comment model
const commentSchema = new mongoose.Schema({
  postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Comment = mongoose.model('Comment', commentSchema);

// Multer setup for file upload
const upload = multer({
  dest: 'uploads/',
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPEG and PNG are allowed.'));
    }
  },
});



// Middleware to check authentication
function isAuthenticated(req, res, next) {
  // Allow unauthenticated access for certain routes
  const publicRoutes = ['/api/posts'];
  if (publicRoutes.includes(req.path)) {
    return next(); // Skip authentication for public routes
  }
  // Apply authentication for other routes
  if (req.session.userId) {
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

// Get Profile Route
app.get('/api/user/profile', async (req, res) => {
  try {
    const { username } = req.query;
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    const user = await User.findOne({ username }).select('username email');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Fetch user posts
    const posts = await Post.find({ userId: user._id });

    const profile = {
      username: user.username,
      email: user.email,
      posts,
      followersCount: 123, // Dummy data
      followingCount: 456, // Dummy data
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

// Create Post Route (Allowing unauthorized access)
app.post('/api/posts', async (req, res) => {
  const { content } = req.body;
  const predefinedUsernames = ['Saibha', 'Alzaahid']; // List of predefined usernames
  const username = req.session?.username || 
                   predefinedUsernames[Math.floor(Math.random() * predefinedUsernames.length)];

  try {
    const newPost = new Post({
      content,
      username, // Use username from session or a random username from the list
      image: null, // Set image to null explicitly
    });

    await newPost.save();
    res.status(201).json({ message: 'Post created successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Error creating post', details: err.message });
  }
});






// Get Posts Route with Pagination
// Get Posts Route with Pagination
app.get('/api/posts', async (req, res) => {
  try {
    const posts = await Post.find(); // No populate needed
    res.json(posts);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching posts', details: err.message });
  }
});



// Like Post Route
app.post('/api/posts/like/:postId', isAuthenticated, async (req, res) => {
  const { postId } = req.params;
  const userId = req.session.userId;

  try {
    const existingLike = await Like.findOne({ postId, userId });

    if (existingLike) {
      return res.status(400).json({ error: 'Post already liked' });
    }

    const like = new Like({ postId, userId });
    await like.save();

    // Update post likes count
    const post = await Post.findById(postId);
    post.likesCount = (post.likesCount || 0) + 1;
    await post.save();

    res.status(201).json({ message: 'Post liked successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Error liking post', details: err.message });
  }
});

// Comment on Post Route
app.post('/api/posts/comment/:postId', isAuthenticated, async (req, res) => {
  const { postId } = req.params;
  const { content } = req.body;
  const userId = req.session.userId;

  try {
    const comment = new Comment({ postId, userId, content });
    await comment.save();

    res.status(201).json({ message: 'Comment added successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Error adding comment', details: err.message });
  }
});

// Get Comments for a Post Route
app.get('/api/posts/comments/:postId', isAuthenticated, async (req, res) => {
  const { postId } = req.params;

  try {
    const comments = await Comment.find({ postId }).populate('userId', 'username');
    res.json(comments);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching comments', details: err.message });
  }
});

// Upload Image Route
app.post('/api/posts/upload', upload.single('image'), async (req, res) => {
  const { file } = req;

  if (!file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  res.json({ imageUrl: `/uploads/${file.filename}` });
});

// Get all users Route
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find(); // Fetch all users from the database
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});


// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
