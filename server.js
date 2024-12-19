// Import required modules
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

app.use(function(req,res,next){
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, PATCH");
  res.header("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization, X-Requested-With");
  next();
});

// Database Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Database connection error:', err));

// Models
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  steamId: {type: String, required: true },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date, default: null },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  friendRequests: [{ 
    from: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    to: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    status: { type: String, enum: ['pending', 'accepted', 'declined'], default: 'pending' }
  }],
  faction: { type: String, enum: ['LONER', 'UKM', 'ECOLOGISTS', 'MERCS', 'CLEAR_SKY', 'BROTHERHOOD', 'DUTY', 'FREEDOM', 'MONOLITH', 'RENEGADES'], default: 'LONER' },
  isOnline: {type: Boolean, default: false}
}));

const Message = mongoose.model('Message', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  content: { type: String, required: true },
  isAnonymous: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
}));

const Note = mongoose.model('Note', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
}));

// Helper Functions
const generateToken = (user) => {
  console.log('generateToken', user);
  return jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

// Routes

// Authentication Routes
app.post('/auth/register', async (req, res) => {
  try {
    const { username, password, steamId } = req.body;
    const passwordHash = await bcrypt.hash(password, 10);
    const user = new User({ username, passwordHash, steamId });
    await user.save();
    const token = generateToken(user);
    res.status(201).json({ token, user });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) return res.status(401).json({ error: 'Invalid credentials' });

    user.lastLogin = new Date();
    user.isOnline = true;
    await user.save();

    const token = generateToken(user);
    res.json({ token, user });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Middleware to Protect Routes
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });

  console.log(authHeader, 'token')
  jwt.verify(authHeader, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

app.post('/auth/logout', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.isOnline = false; // Mark as offline
    await user.save();

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// User Routes
app.post('/users', async (req, res) => {
  try {
    const user = new User(req.body);
    await user.save();
    res.status(201).json(user);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/users/:id', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).populate('friends');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/messages/global', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 10; // Default to 10 messages per page

    const totalMessages = await Message.countDocuments({ recipientId: null });
    const totalPages = Math.ceil(totalMessages / limit);
    const messages = await Message.find({ recipientId: null })
      .populate('userId', 'username faction')
      .sort({ createdAt: -1 }) // Sort by newest messages first
      .skip((page - 1) * limit)
      .limit(limit);

    res.json({
      metadata: {
        totalMessages,
        currentPage: page,
        totalPages,
        limit,
      },
      messages,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Direct Messages with Pagination
app.get('/messages/direct', authenticate, async (req, res) => {
  try {
    const { recipientId, page = 1, limit = 10 } = req.query;
    if (!recipientId) {
      return res.status(400).json({ error: 'Recipient ID is required' });
    }

    const skip = (page - 1) * limit;

    const messages = await Message.find({
      $or: [
        { userId: req.user.id, recipientId },
        { userId: recipientId, recipientId: req.user.id },
      ],
    })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .populate('userId', 'username faction')
      .populate('recipientId', 'username faction');

    const totalMessages = await Message.countDocuments({
      $or: [
        { userId: req.user.id, recipientId },
        { userId: recipientId, recipientId: req.user.id },
      ],
    });

    res.json({
      page: parseInt(page),
      limit: parseInt(limit),
      totalMessages,
      totalPages: Math.ceil(totalMessages / limit),
      messages,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/messages', authenticate, async (req, res) => {
  try {
    const message = new Message({ ...req.body, userId: req.user.id });
    console.log(req.body);
    await message.save();
    res.status(201).json(message);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Notes Routes
app.get('/notes/:userId', authenticate, async (req, res) => {
  try {
    const notes = await Note.find({ userId: req.params.userId });
    res.json(notes);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/notes', authenticate, async (req, res) => {
  try {
    const note = new Note({ ...req.body, userId: req.user.id });
    await note.save();
    res.status(201).json(note);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/notes/:id', authenticate, async (req, res) => {
  try {
    const note = await Note.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!note) return res.status(404).json({ error: 'Note not found' });
    res.json(note);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/notes/:id', authenticate, async (req, res) => {
  try {
    const note = await Note.findByIdAndDelete(req.params.id);
    if (!note) return res.status(404).json({ error: 'Note not found' });
    res.json({ message: 'Note deleted successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Friend Request Routes

// Send a Friend Request
app.post('/friend-requests', authenticate, async (req, res) => {
  try {
    const { toUserId } = req.body;

    if (req.user.id === toUserId) {
      return res.status(400).json({ error: "You can't send a friend request to yourself." });
    }

    const toUser = await User.findById(toUserId);
    if (!toUser) return res.status(404).json({ error: 'User not found' });

    const isAlreadyFriend = toUser.friends.includes(req.user.id);
    if (isAlreadyFriend) return res.status(400).json({ error: 'User is already your friend.' });

    const existingRequest = toUser.friendRequests.find(
      (req) => req.from.toString() === req.user.id
    );
    if (existingRequest) return res.status(400).json({ error: 'Friend request already sent.' });

    // Add friend request
    toUser.friendRequests.push({ from: req.user.id, to: toUserId });
    await toUser.save();
    res.status(201).json({ message: 'Friend request sent successfully.' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Accept Friend Request
app.post('/friend-requests/:id/accept', authenticate, async (req, res) => {
  try {
    const requestId = req.params.id;

    const user = await User.findById(req.user.id).populate('friendRequests.from');
    const request = user.friendRequests.find((req) => req._id.toString() === requestId);

    if (!request || request.status !== 'pending') {
      return res.status(404).json({ error: 'Friend request not found or already processed.' });
    }

    // Add each other as friends
    user.friends.push(request.from._id);
    const otherUser = await User.findById(request.from._id);
    otherUser.friends.push(req.user.id);

    // Update request status
    request.status = 'accepted';
    await user.save();
    await otherUser.save();

    res.json({ message: 'Friend request accepted.' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Decline Friend Request
app.post('/friend-requests/:id/decline', authenticate, async (req, res) => {
  try {
    const requestId = req.params.id;

    const user = await User.findById(req.user.id);
    const request = user.friendRequests.find((req) => req._id.toString() === requestId);

    if (!request || request.status !== 'pending') {
      return res.status(404).json({ error: 'Friend request not found or already processed.' });
    }

    // Update request status
    request.status = 'declined';
    await user.save();

    res.json({ message: 'Friend request declined.' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// View Friend Requests
app.get('/friend-requests', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).populate('friendRequests.from', 'username');
    const incomingRequests = user.friendRequests.filter((req) => req.status === 'pending');
    res.json(incomingRequests);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
