const express = require('express'); // Importing express for creating server
const mongoose = require('mongoose'); // Importing mongoose for database operations
const jwt = require('jsonwebtoken'); // Importing jsonwebtoken for token generation
const bcrypt = require('bcrypt'); // Importing bcrypt for password hashing
const crypto = require('crypto'); // Importing crypto for generating random strings
const helmet = require('helmet'); // Importing helmet for security headers
const rateLimit = require('express-rate-limit').rateLimit; // Importing express-rate-limit for rate limiting
const session = require('express-session'); // Importing express-session for session management
// const GoogleStrategy = require('passport-google-oauth20').Strategy;  Importing passport-google-oauth20 for Google OAuth2.0 strategy
// const passport = require('passport');  Importing passport for authentication
require('dotenv').config(); // For environment variables
const cookieParser = require('cookie-parser'); // Importing cookie-parser for parsing cookies
const nodemailer = require('nodemailer'); // Importing nodemailer for sending emails
const cors = require('cors'); // Importing cors for enabling CORS
const multer = require('multer'); // Importing multer for file uploads
const path = require('path'); // Importing path for file path operations
// const WebSocket = require('ws');
// const gpsd = require('node-gpsd');
const app = express(); // Creating an instance of express
// const csrffProtection = require('csurf')();


// app.use(csrffProtection);

// // Add CSRF token to responses
// app.get('/csrf-token', (req, res) => {
//   res.json({ csrfToken: req.csrfToken() });


// });

// Middleware
app.use(helmet.referrerPolicy({ policy: 'no-referrer' }));
app.use(helmet.dnsPrefetchControl({ allow: false }));
app.use(helmet.frameguard({ action: 'deny' }));


app.use(cors({ origin: '*', credentials: true })); // Enabling CORS
app.use(express.json()); // Parsing incoming request bodies as JSON
app.use(helmet()); // Adding security headers
app.use(cookieParser()); // Parsing cookies
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'itsmysecret', // Replace with a strong secret in production
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
    },
  })
);
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({
    message: 'An error occurred',
    error: process.env.NODE_ENV === 'production' ? undefined : err.message,
  });
});

// app.use(passport.initialize());
// app.use(passport.session());

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit to 100 requests per IP
  message: 'Too many requests, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
const isOriginalAdmin = (req, res, next) => {
  const userId = req.user.userId; // Get userId from the authenticated token
  const originalAdminEmail = process.env.ADMIN_EMAIL; // The email of the original admin

  // Check if the authenticated user is the original admin
  if (req.user.email !== originalAdminEmail) {
    return res.status(403).json({ message: 'Access denied. Only the original admin can perform this action.' });
  }

  next(); // Proceed to the next middleware or route handler
};


// Apply global limiter to specific routes
app.use( generalLimiter);


// MongoDB Connection
mongoose
  .connect("mongodb+srv://chand261726:Chand%402617@cluster0.kh2ty.mongodb.net/Usermanagement?retryWrites=true&w=majority&appName=Cluster0", { // Connecting to MongoDB
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('Connected to MongoDB')) // Logging successful connection
  .catch((err) => console.error('MongoDB connection error:', err)); // Logging connection error

// Schemas and Models 
const userSchema = new mongoose.Schema({ // Creating a user schema
  firstName: { type: String, required: true, trim: true, minlength: 1 }, // First name of the user
  lastName: { type: String, required: true, trim: true, minlength: 1 }, // Last name of the user
  email: { type: String, unique: true, trim: true, lowercase: true }, // Email of the user
  phone: { type: Number, unique: true, sparse: true }, // Phone number of the user
  password: { type: String, minlength: 8 }, // Password of the user
  refreshTokens: { type: [String], default: [] },// REFRESH TOKEN
  role: { type: String, enum: ['user', 'admin', 'superadmin'], default: 'user' }, // Role of the user
  userId: { type: String, unique: true, required: true }, // Unique ID of the user
}, { timestamps: true }); // Adding timestamps to the schema

const tableSchema = new mongoose.Schema({ // Creating a table schema
  userId: { type: String, required: true, unique: true }, // Unique ID of the user
  username: { type: String, required: true }, // Username of the user
  value: { type: String, required: true }, // Value of the user
});

const trackingSchema = new mongoose.Schema({ // Creating a tracking schema
  userId: { type: String, required: true }, // Unique ID of the user
  username: { type: String, required: true }, // Username of the user
  tableNumber: { type: Number, required: true }, // Table number of the user
  value: { type: String, required: true }, // Value of the user
});
// models/Activity.js

const activitySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    plantName: { type: String, required: true },
    height: { type: Number, required: true },
    area: { type: String, required: true },
    event: { type: String, required: true },
    userName: { type: String, required: true },
    userMobile: { type: String, required: true },
    plantedDate: { type: Date, default: Date.now },
    prePlantationImage: { type: String, required: true },
    plantationImage: { type: String, required: true },
    location: { type: String, required: true },
    treeCategory: { type: String, required: true }, // Added treeCategory field
}, { timestamps: true });

const Activity = mongoose.model('Activity', activitySchema);

// models/TreeCategory.js

const treeCategorySchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, required: true },
    icon: { type: String, required: true }, // You can store the icon as a string (e.g., a URL or a class name)
});

const TreeCategory = mongoose.model('TreeCategory', treeCategorySchema);
module.exports = TreeCategory;
const User = mongoose.model('User', userSchema); // Creating a User model
const Table1 = mongoose.model('Table1', tableSchema); // Creating a Table1 model
const Table2 = mongoose.model('Table2', tableSchema); // Creating a Table2 model
const Table3 = mongoose.model('Table3', tableSchema); // Creating a Table3 model
const TrackingTable = mongoose.model('TrackingTable', trackingSchema); // Creating a TrackingTable model

// Utility Functions
const jwtSecret = process.env.JWT_SECRET || 'thisissecret'; // JWT secret key
const jwtRefreshSecret = process.env.JWT_REFRESH_SECRET || 'thisisrefreshsecret'; // JWT refresh secret key

// Function to determine table number dynamically
const getTableNumber = (alphabet) => {
  if (!alphabet || typeof alphabet !== 'string') {
    console.error(`Invalid input: "${alphabet}". Expected a single character.`);
    return null;                                                                                           
  }
  const charCode = alphabet.charCodeAt(0);
  if (charCode >= 65 && charCode <= 90) { // A-Z
    // Map letters to table numbers (A-I: 1, J-R: 2, S-Z: 3)
    if (charCode <= 73) return 1; // A-I
    if (charCode <= 82) return 2; // J-R                                                                                                                           
    return 3; // S-Z
  }
  console.error(`Input "${alphabet}" is not a valid uppercase letter.`);
  return null;
};

// Function to save user to a table
const saveUserToTable = async (user) => {
  const { firstName, lastName, userId } = user;

  if (!firstName) {
    throw new Error('First name is required to determine table number.');
  }

  const fullName = `${firstName} ${lastName}`;
  const alphabet = firstName.charAt(0).toUpperCase();
  const tableNumber = getTableNumber(alphabet);

  if (!tableNumber) {
    throw new Error(`Failed to map "${alphabet}" to a valid table.`);
  }

  let savedRecord;
  switch (tableNumber) {
    case 1: // A-I
      savedRecord = await Table1.create({ userId, username: fullName, value: alphabet });
      break;
    case 2: // J-R
      savedRecord = await Table2.create({ userId, username: fullName, value: alphabet });
      break;
    case 3: // S-Z
      savedRecord = await Table3.create({ userId, username: fullName, value: alphabet });
      break;
    default:
      throw new Error('Unexpected table number.');
  }

  await TrackingTable.create({
    userId,
    username: fullName,
    tableNumber,
    value: alphabet,
  });

  return { tableNumber, savedRecord };
};
const imageSchema = new mongoose.Schema(
  {
    userId: { type: String, required: true, index: true },
    filename: { type: String, required: true },
    path: { type: String, required: true },
    PlantName: { type: String, required: true },
    PlantHeight: { type: String, required: true },
    EventName: { type: String, required: true },
    size: { type: Number, required: true },
    mimetype: { type: String, required: true },
    imageType: { type: String, enum: ['urban', 'rural'], required: true },
    subType: { type: String, enum: ['pre-plantation', 'tree'], required: true },
  },
  { timestamps: true } // Automatically adds createdAt and updatedAt fields
);

const Image = mongoose.model('Image', imageSchema);
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1]; // Extract the token from the "Authorization" header

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  try {
    const decoded = verifyAccessToken(token);
    req.user = decoded;  // Save the decoded token to `req.user`
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Invalid or expired access token' });
  }
};
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`);
  },
});

const fileFilter = (req, file, cb) => {
  const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/jpg'];
  if (!allowedMimeTypes.includes(file.mimetype)) {
    return cb(new Error('Only .png, .jpg, and .jpeg formats are allowed!'), false);
  }
  cb(null, true);
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // Max 5MB file size
  fileFilter: fileFilter,
});
const authentication = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]; // Extract the token from the "Authorization" header
  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Invalid or expired access token' });
  }
};

const generateOTP = () => {
  return crypto.randomInt(100000, 999999).toString(); // Generate 6-digit OTP
};

const sendOTP = (mobile, otp) => {
  console.log(`Sending OTP: ${otp} to ${mobile}`);
  return true; // Simulate OTP sending (Integrate an SMS service for production)
};

const storeOTP = (mobile, otp, ttl = 5 * 60 * 1000) => {
  // Store OTP with expiry time (default 5 minutes)
  otpCache.set(mobile, { otp, expiresAt: Date.now() + ttl });
};

const validateOTP = (mobile, inputOtp) => {
  const entry = otpCache.get(mobile);
  if (!entry) return { valid: false, message: 'OTP not found or expired.' };

  if (Date.now() > entry.expiresAt) {
    otpCache.delete(mobile);
    return { valid: false, message: 'OTP expired.' };
  }

  if (entry.otp !== inputOtp) return { valid: false, message: 'Invalid OTP.' };

  otpCache.delete(mobile); // OTP is valid, remove it
  return { valid: true, message: 'OTP validated successfully.' };
};

function checkImageTypeAndSubType(req, res, next) {
  const { imageType, subType } = req.body;
  const validImageTypes = ['urban', 'rural'];
  const validSubTypes = ['pre-plantation', 'tree'];

  // Validate imageType and subType presence
  if (!imageType || !subType) {
    return res.status(400).json({ message: 'Both imageType and subType are required.' });
  }

  // Validate imageType
  if (!validImageTypes.includes(imageType)) {
    return res.status(400).json({ message: `Invalid imageType. Allowed values: ${validImageTypes.join(', ')}.` });
  }

  // Validate subType
  if (!validSubTypes.includes(subType)) {
    return res.status(400).json({ message: `Invalid subType. Allowed values: ${validSubTypes.join(', ')}.` });
  }

  next(); // Proceed if all validations pass
}

// Function to check user registration
const checkUserRegistered = async (mobile) => {
  let user = await User.findOne({ phone: mobile });
  return user ? user : null;
};

// Route: Send OTP if user is registered
app.post('/send-otp', async (req, res) => {
  const { mobile, name } = req.body;

  if (!mobile || !/^\d+$/.test(mobile)) {
    return res.status(400).json({ message: 'Invalid phone number' });
  }

  if (!name || name.trim().length === 0) {
    return res.status(400).json({ message: 'Name is required' });
  }

  const user = await checkUserRegistered(mobile);
  if (!user) {
    return res.status(400).json({ message: 'User not registered' });
  }

  const otp = generateOTP();
  otpCache[mobile] = { otp, timestamp: Date.now() };
  console.log(`Sending OTP: ${otp} to ${mobile}`);

  return res.status(200).json({ message: 'OTP sent successfully' });
});
// Route to get all users with pagination (Admin only)
app.get('/users', authenticateToken, async (req, res) => {
  const { page = 1, limit = 10 } = req.query; // Default to page 1 and limit 10

  // Check if the user is an admin
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') {
    return res.status(403).json({ message: 'Access denied' });
  }

  try {
    const users = await User.find()
      .skip((page - 1) * limit) // Skip the previous pages
      .limit(Number(limit)); // Limit the number of results

    const totalUsers = await User.countDocuments(); // Get total count of users

    res.status(200).json({
      users,
      totalPages: Math.ceil(totalUsers / limit), // Calculate total pages
      currentPage: Number(page),
      totalUsers,
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Error fetching users', error: error.message });
  }
});
app.get('/admin/dashboard', authenticateToken, async (req, res) => {
  // Check if the user is an admin
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') {
    return res.status(403).json({ message: 'Access denied. Only admins can view the dashboard.' });
  }

  try {
    // Fetch total counts
    const totalUsers = await User.countDocuments();
    const totalActivities = await Activity.countDocuments();
    const totalEvents = await Event.countDocuments();

    // Fetch recent activities (last 10 actions)
    const recentActivities = await Activity.find()
      .sort({ timestamp: -1 })
      .limit(10)
      .select('userId action timestamp');

    res.status(200).json({
      totalUsers,
      totalActivities,
      totalEvents,
      recentActivities,
    });
  } catch (error) {
    console.error('Error fetching dashboard data:', error);
    res.status(500).json({ message: 'Error fetching dashboard data', error: error.message });
  }
});
// Route to get all activities with pagination (Admin only)
app.get('/activities', authenticateToken, async (req, res) => {
  const { page = 1, limit = 10 } = req.query; // Default to page 1 and limit 10

  // Check if the user is an admin
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') {
    return res.status(403).json({ message: 'Access denied' });
  }

  try {
    const activities = await Activity.find()
      .skip((page - 1) * limit) // Skip the previous pages
      .limit(Number(limit)); // Limit the number of results

    const totalActivities = await Activity.countDocuments(); // Get total count of activities

    res.status(200).json({
      activities,
      totalPages: Math.ceil(totalActivities / limit), // Calculate total pages
      currentPage: Number(page),
      totalActivities,
    });
  } catch (error) {
    console.error('Error fetching activities:', error);
    res.status(500).json({ message: 'Error fetching activities', error: error.message });
  }
});
// Route: Verify OTP & Register User
app.post('/verify-registration-otp', async (req, res) => {
  const { phone, otp, firstName, lastName } = req.body;
  const otpData = otpCache[phone];

  if (!otpData) {
    return res.status(400).json({ message: 'OTP not sent or expired' });
  }

  if (Date.now() - otpData.timestamp > 5 * 60 * 1000) {
    delete otpCache[phone];
    return res.status(400).json({ message: 'OTP expired, request a new one' });
  }

  if (otpData.otp !== otp) {
    return res.status(400).json({ message: 'Invalid OTP' });
  }

  delete otpCache[phone]; // Remove OTP after verification

  const userId = crypto.randomUUID();

  const newUser = new User({
    firstName,
    lastName,
    phone,
    userId,
    role: 'user',
  });

  await newUser.save();

  const token = jwt.sign({ userId: newUser.userId, role: newUser.role }, process.env.JWT_SECRET, {
    expiresIn: '1h',
  });

  const refreshToken = jwt.sign({ userId: newUser.userId, role: newUser.role }, process.env.JWT_SECRET, {
    expiresIn: '7d',
  });

  return res.status(201).json({ message: 'User registered successfully', token, refreshToken });
});


// Token Generation Functions
const generateToken = (userId, role) => {
  return jwt.sign({ userId, role }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRATION_TIME || '15m',
  });
};

const generateRefreshToken = (userId, role) => {
  return jwt.sign({ userId, role }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRATION_TIME || '7d',
  });
};

// Token Verification Functions
const verifyAccessToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET);
};

const verifyRefreshToken = (token) => {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
};

// Middleware to authenticate token

// Middleware to check if the user is the original admin


// Route to create a super admin
app.post('/create-super-admin', authenticateToken, isOriginalAdmin, async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  try {
    // Validate input
    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Check for existing super admin
    const existingSuperAdmin = await User.findOne({ email });
    if (existingSuperAdmin) {
      return res.status(400).json({ message: 'Super admin with this email already exists.' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, parseInt(process.env.SALT_ROUNDS) || 10);
    const userId = crypto.randomUUID();

    // Create the new super admin
    const newSuperAdmin = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      userId,
      role: 'superadmin',
    });

    await newSuperAdmin.save();

    res.status(201).json({ message: 'Super admin created successfully', userId: newSuperAdmin.userId });
  } catch (error) {
    console.error('Error creating super admin:', error);
    res.status(500).json({ message: 'Error creating super admin', error: error.message });
  }
});
// Protect routes like this
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'You have access to this route', user: req.user });
});
// Route to create or update password
app.post('/create-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const userId = req.user.userId; // Get userId from the authenticated token

  try {
    // Validate input
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: 'New password and confirm password do not match' });
    }

    // Check password strength (you can customize this regex)
    if (!/^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/.test(newPassword)) {
      return res.status(400).json({
        message: 'Password must be at least 8 characters long, contain at least one uppercase letter, one number, and one special character (!@#$%^&*)'
      });
    }

    // Find the user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if the current password is correct
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }

    // Hash the new password
    const hashedNewPassword = await bcrypt.hash(newPassword, parseInt(process.env.SALT_ROUNDS) || 10);

    // Update the user's password
    user.password = hashedNewPassword;
    await user.save();

    res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Error updating password:', error);
    res.status(500).json({ message: 'Error updating password', error: error.message });
  }
});

const authorizeRoles = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied' });
    }
    next();
  };
};

// Route to promote a user
app.post('/promote-user', authenticateToken, authorizeRoles('admin', 'superadmin'), async (req, res) => {
  const { userId, newRole } = req.body;

  const validRoles = ['admin', 'superadmin'];
  if (!validRoles.includes(newRole)) {
    return res.status(400).json({ message: `Invalid role. Allowed roles are: ${validRoles.join(', ')}` });
  }

  try {
    const userToPromote = await User.findOne({ userId });
    if (!userToPromote) {
      return res.status(404).json({ message: 'User not found' });
    }

    userToPromote.role = newRole;
    await userToPromote.save();

    res.status(200).json({ message: `User promoted to ${newRole} successfully`, user: userToPromote });
  } catch (error) {
    console.error('Error promoting user:', error);
    res.status(500).json({ message: 'Error promoting user', error: error.message });
  }
});

// Route to create a new tree category
app.post('/tree-categories', async (req, res) => {
  const { name, description, icon } = req.body;

  try {
      const newCategory = new TreeCategory({ name, description, icon });
      await newCategory.save();
      res.status(201).json({ message: 'Tree category created successfully!', category: newCategory });
  } catch (error) {
      console.error('Error creating tree category:', error);
      res.status(500).json({ message: 'Error creating tree category', error: error.message });
  }
});


// Route to refresh token
app.post('/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) return res.status(401).json({ message: 'No refresh token provided' });

  try {
    const decoded = verifyRefreshToken(refreshToken);

    // Find the user by the decoded refresh token info (i.e., userId)
    const user = await User.findOne({ userId: decoded.userId });
    if (!user) return res.status(403).json({ message: 'Invalid refresh token' });

    // Generate a new access token and refresh token
    const newAccessToken = generateToken(user.userId, user.role);
    const newRefreshToken = generateRefreshToken(user.userId, user.role);

    // Update refresh token in DB if necessary
    user.refreshTokens.push(refreshToken);
    await user.save();

    res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch (error) {
    res.status(403).json({ message: 'Invalid or expired refresh token' });
  }
});
// Route to get user history and recent activities with pagination
app.get('/user-history', authenticateToken, async (req, res) => {
  const { page = 1, limit = 10 } = req.query; // Default to page 1 and limit 10
  const userId = req.user.userId; // Get userId from the authenticated token

  try {
      const activities = await Activity.find({ userId })
          .sort({ createdAt: -1 }) // Sort by most recent
          .skip((page - 1) * limit) // Skip the previous pages
          .limit(Number(limit)); // Limit the number of results

      const totalActivities = await Activity.countDocuments({ userId }); // Get total count of activities

      // Map activities to match PlantationHistory interface
      const historyData = activities.map(activity => ({
          id: activity._id.toString(),
          plantName: activity.plantName,
          height: activity.height,
          area: activity.area,
          event: activity.event,
          userName: activity.userName,
          userMobile: activity.userMobile,
          plantedDate: activity.plantedDate.toISOString().split('T')[0], // Format date
          prePlantationImage: activity.prePlantationImage,
          plantationImage: activity.plantationImage,
          location: activity.location,
          treeCategory: activity.treeCategory, // Include tree category
      }));

      res.status(200).json({
          activities: historyData,
          totalPages: Math.ceil(totalActivities / limit), // Calculate total pages
          currentPage: Number(page),
          totalActivities,
      });
  } catch (error) {
      console.error('Error fetching user history:', error);
      res.status(500).json({ message: 'Error fetching user history', error: error.message });
  }
});

// Route for user signup
app.post('/signup', async (req, res) => {
  const { firstName, lastName, email, password, confirmPassword, phone } = req.body;

  try {
    // Validate input
    if (!/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }

    if (!/^\d+$/.test(phone)) {
      return res.status(400).json({ message: 'Invalid phone number: Only numbers are allowed' });
    }

    if (!/^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/.test(password)) {
      return res.status(400).json({ 
        message: 'Password must be at least 8 characters long, contain at least one uppercase letter, one number, and one special character (!@#$%^&*)' 
      });
    }
    

    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Password and confirm password do not match' });
    }

    // Check for duplicate email and phone
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists.' });
    }

    const existingPhone = await User.findOne({ phone });
    if (existingPhone) {
      return res.status(400).json({ message: 'Phone number already exists.' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, parseInt(process.env.SALT_ROUNDS) || 10);
    const userId = crypto.randomUUID();
    const defaultRole = 'user';

    // Create user
    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      phone,
      userId,
      role: defaultRole,
    });

    await newUser.save();

    // Save user to external table
    let tableNumber, savedRecord;
    try {
      const result = await saveUserToTable({ firstName, lastName, email, userId });
      tableNumber = result.tableNumber;
      savedRecord = result.savedRecord;
    } catch (err) {
      return res.status(500).json({
        message: 'Error saving user to external table',
        error: err.message,
      });
    }

    // Generate tokens
    const token = generateToken(newUser.userId, newUser.role);
    const refreshToken = generateRefreshToken(newUser.userId, newUser.role);

    res.status(201).json({
      message: 'User created successfully',
      token,
      refreshToken,
      savedToTable: tableNumber,
      tableRecord: savedRecord,
    });
  } catch (err) {
    console.error('Error creating user:', err.message);
    res.status(500).json({ message: 'Error creating user', error: err.message });
  }
});
// const initializeAdmin = async () => {
//   const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
//   const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';

//   try {
//     const adminExists = await User.findOne({ email: adminEmail });
//     if (adminExists) {
//       console.log('Admin already initialized.');
//       return;
//     }

//     const hashedPassword = await bcrypt.hash(adminPassword, parseInt(process.env.SALT_ROUNDS) || 10);
//     const admin = new User({
//       firstName: 'Admin',
//       lastName: 'User',
//       email: adminEmail,
//       password: hashedPassword,
//       userId: crypto.randomUUID(),
//       role: 'superadmin',
//     });

//     await admin.save();
//     console.log('Admin user initialized successfully.');
//   } catch (err) {
//     console.error('Failed to initialize admin user:', err.message);
//   }
// };


// // Call this after connecting to MongoDB
// initializeAdmin();

// Route to get user profile
// Route to get user profile
// Route to get user profile
app.get('/profile', authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
      const user = await User.findById(userId).select('-password'); // Exclude password
      if (!user) return res.status(404).json({ message: 'User not found' });

      // Fetch recent activity (assuming you have an Activity model)
      const recentActivity = await Activity.find({ userId })
          .sort({ createdAt: -1 })
          .limit(3) // Get the last 3 activities
          .select('date action'); // Select only the fields you need

      // Format the response
      res.status(200).json({
          name: `${user.firstName} ${user.lastName}`,
          email: user.email,
          phone: user.phone,
          treesPlanted: user.treesPlanted,
          badge: user.badge,
          recentActivity: recentActivity.map(activity => ({
              date: activity.date.toISOString().split('T')[0], // Format date
              action: activity.action
          }))
      });
  } catch (error) {
      console.error('Error fetching user profile:', error);
      res.status(500).json({ message: 'Error fetching user profile', error: error.message });
  }
});

// Route to update user profile
app.put('/profile', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const { firstName, lastName, email, phone } = req.body;

  try {
      const updatedUser = await User.findByIdAndUpdate(userId, { firstName, lastName, email, phone }, { new: true });
      if (!updatedUser) return res.status(404).json({ message: 'User not found' });
      res.status(200).json({ message: 'Profile updated successfully', user: updatedUser });
  } catch (error) {
      console.error('Error updating profile:', error);
      res.status(500).json({ message: 'Error updating profile', error: error.message });
  }
});

// Route to delete user account
app.delete('/profile', authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
      const deletedUser = await User.findByIdAndDelete(userId);
      if (!deletedUser) return res.status(404).json({ message: 'User not found' });
      res.status(200).json({ message: 'User account deleted successfully' });
  } catch (error) {
      console.error('Error deleting account:', error);
      res.status(500).json({ message: 'Error deleting account', error: error.message });
  }
});

// Route to update user password
app.post('/profile/password', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const { currentPassword, newPassword, confirmPassword } = req.body;

  try {
      // Validate input
      if (!currentPassword || !newPassword || !confirmPassword) {
          return res.status(400).json({ message: 'All fields are required' });
      }

      if (newPassword !== confirmPassword) {
          return res.status(400).json({ message: 'New password and confirm password do not match' });
      }

      // Find the user
      const user = await User.findById(userId);
      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }

      // Check if the current password is correct
      const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
      if (!isCurrentPasswordValid) {
          return res.status(400).json({ message: 'Current password is incorrect' });
      }

      // Hash the new password
      const hashedNewPassword = await bcrypt.hash(newPassword, parseInt(process.env.SALT_ROUNDS) || 10);

      // Update the user's password
      user.password = hashedNewPassword;
      await user.save();

      res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
      console.error('Error updating password:', error);
      res.status(500).json({ message: 'Error updating password', error: error.message });
  }
});


// Route to update user profile
app.put('/profile', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const { firstName, lastName

, email, phone } = req.body;

  try {
    const updatedUser = await userModel.findByIdAndUpdate(userId, { firstName, lastName, email, phone }, { new: true });
    res.status(200).json({ message: 'Profile updated successfully', user: updatedUser });
  } catch (error) {
    res.status(500).json({ message: 'Error updating profile', error: error.message });
  }
});

// Apply rate limit to login route
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: 'Too many login attempts, please try again later.',
});

// Route to login
app.post('/login', loginLimiter,async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Generate tokens
    const token = generateToken(user.userId, user.role);
    const refreshToken = generateRefreshToken(user.userId, user.role);
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Secure cookies in production
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
    

    res.json({
      message: 'Login successful',
      token,
      refreshToken: 'Stored in HTTP-only secure cookie'
    });
    
  } catch (err) {
    console.error('Error logging in:', err.message);
    res.status(500).json({ message: 'Error logging in', error: err.message });
  }
});

// Route to handle tree plantation uploads
app.post('/upload', upload.fields([
  { name: 'prePlantationImage', maxCount: 1 },
  { name: 'plantationImage', maxCount: 1 }
]), async (req, res) => {
  const {
      userMobile,
      userName,
      plantName,
      height,
      event,
      area,
      userIp,
      userLocation,
      latitude,
      longitude,
      district,
      gpName,
      categoryId // New field for tree category
  } = req.body;

  try {
      // Validate required fields
      if (!userMobile || !plantName || !height || !event || !area || !categoryId) {
          return res.status(400).json({ message: 'All fields are required!' });
      }

      // Verify user registration
      const user = await checkUserRegistered(userMobile);
      if (!user) {
          return res.status(404).json({ message: 'User not found. Please register first.' });
      }

      // Validate uploaded files
      if (!req.files || !req.files.prePlantationImage || !req.files.plantationImage) {
          return res.status(400).json({ message: 'Both images are required!' });
      }

      // Extract image metadata
      const prePlantationImage = req.files.prePlantationImage[0];
      const plantationImage = req.files.plantationImage[0];

      // Save plantation entry
      const newEntry = new Plantation({
          userId: user.userId,
          plantName,
          height,
          event,
          area,
          userIp,
          userLocation,
          latitude,
          longitude,
          district,
          gpName,
          categoryId, // Save the selected category ID
          prePlantationImage: {
              filename: prePlantationImage.filename,
              path: prePlantationImage.path,
              size: prePlantationImage.size,
              mimetype: prePlantationImage.mimetype,
          },
          plantationImage: {
              filename: plantationImage.filename,
              path: plantationImage.path,
              size: plantationImage.size,
              mimetype: plantationImage.mimetype,
          },
      });

      await newEntry.save();

      // Save activity record
      const newActivity = new Activity({
          userId: user.userId,
          plantName,
          event,
          area,
          categoryId // Save the selected category ID in activity as well
      });

      await newActivity.save();

      res.status(201).json({
          message: 'Data and images uploaded successfully!',
          plantation: newEntry,
      });
  } catch (error) {
      console.error('Error processing request:', error);
      res.status(500).json({ message: 'Error processing request', error: error.message });
  }
});

app.get('/profile', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const user = await User.findById(userId);
  if (!user) return res.status(404).json({ message: 'User not found' });
  res.status(200).json({ user });
});
app.put('/profile', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const { firstName, lastName, email, phone } = req.body;

  try {
    const updatedUser = await User.findByIdAndUpdate(userId, { firstName, lastName, email, phone }, { new: true });
    res.status(200).json({ message: 'Profile updated successfully', user: updatedUser });
  } catch (error) {
    res.status(500).json({ message: 'Error updating profile', error: error.message });
  }
});
app.delete('/profile', authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    await User.findByIdAndDelete(userId);
    res.status(200).json({ message: 'User account deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting account', error: error.message });
  }
});

// Route to create or update password
app.post('/create-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const userId = req.user.userId; // Get userId from the authenticated token

  try {
    // Validate input
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: 'New password and confirm password do not match' });
    }

    // Check password strength (you can customize this regex)
    if (!/^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/.test(newPassword)) {
      return res.status(400).json({
        message: 'Password must be at least 8 characters long, contain at least one uppercase letter, one number, and one special character (!@#$%^&*)'
      });
    }

    // Find the user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if the current password is correct
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }

    // Hash the new password
    const hashedNewPassword = await bcrypt.hash(newPassword, parseInt(process.env.SALT_ROUNDS) || 10);

    // Update the user's password
    user.password = hashedNewPassword;
    await user.save();

    res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Error updating password:', error);
    res.status(500).json({ message: 'Error updating password', error: error.message });
  }
});
// Middleware to check if the user is the original admin

// Route to create a super admin
app.post('/create-super-admin', authenticateToken, isOriginalAdmin, async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  try {
    // Validate input
    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Check for existing super admin
    const existingSuperAdmin = await User.findOne({ email });
    if (existingSuperAdmin) {
      return res.status(400).json({ message: 'Super admin with this email already exists.' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, parseInt(process.env.SALT_ROUNDS) || 10);
    const userId = crypto.randomUUID();

    // Create the new super admin
    const newSuperAdmin = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      userId,
      role: 'superadmin',
    });

    await newSuperAdmin.save();

    res.status(201).json({ message: 'Super admin created successfully', userId: newSuperAdmin.userId });
  } catch (error) {
    console.error('Error creating super admin:', error);
    res.status(500).json({ message: 'Error creating super admin', error: error.message });
  }
});

// Password Reset Email Transporter (Nodemailer)
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});
app.post('/logout', async (req, res) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken) return res.status(400).json({ message: 'No refresh token provided' });

  const user = await User.findOne({ refreshTokens: refreshToken });
  if (user) {
    user.refreshTokens = user.refreshTokens.filter((token) => token !== refreshToken);
    await user.save();
  }

  res.clearCookie('refreshToken');
  res.json({ message: 'Logged out successfully' });
});
// Route to Request a Password Reset
app.post('/reset-password-request', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const resetToken = jwt.sign({ userId: user.id }, jwtSecret, { expiresIn: '1h' });
    const resetLink = `${process.env

.FRONTEND_URL}/reset-password/${resetToken}`;

    // Send email with reset link
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,


      subject: 'Password Reset Request',
      html: `<p>Click <a href="${resetLink}">here</a> to reset your password.</p>`,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Password reset email sent' });
  } catch (err) {
    console.error(err

);
    res.status(500).json({ message: 'Something went wrong' });
  }
});

// Route to Reset the Password
app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  try {
    const decoded = jwt.verify(token, jwtSecret);
    const user = await userModel.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.status(200).json({ message: 'Password has been reset successfully' });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(400).json({ message: 'Reset token has expired' });
    } else if (err.name === 'JsonWebTokenError') {
      return res.status(400).json({ message: 'Invalid reset token' });
    }
    console.error(err);
    res.status(500).json({ message: 'Something went wrong' });
  }
});


// const wss = new WebSocket.Server({ app });

// app.use(express.static('public'));

// GPS Listener Setup
// const gpsListener = new gpsd.Listener();

// gpsListener.on('TPV', (data) => {
//   if (data.lat && data.lon) {
//     const location = { latitude: data.lat, longitude: data.lon };
//     console.log('GPS Location:', location);

//     // Broadcast location to all WebSocket clients
//     wss.clients.forEach((client) => {
//       if (client.readyState === WebSocket.OPEN) {
//         client.send(JSON.stringify(location));
//       }
//     });
//   }
// });

// // Start GPS tracking
// gpsListener.connect(() => gpsListener.watch());

// // Route to get GPS location
// app.get('/location', (req, res) => {
//   if (!gpsListener) {
//     return res.status(500).json({ error: 'GPS not available' });
//   }

//   gpsListener.once('TPV', (data) => {
//     if (data.lat && data.lon) {
//       res.json({ latitude: data.lat, longitude: data.lon });
//     } else {
//       res.status(404).json({ error: 'No GPS data' });
//     }
//   });
// });

// // Fallback IP-based location
// app.get('/ip-location', async (req, res) => {
//   try {
//     const ip = req.ip;
//     const response = await axios.get(`http://ip-api.com/json/${ip}`);
    
//     if (response.data.status === 'success') {
//       res.json({ latitude: response.data.lat, longitude: response.data.lon });
//     } else {
//       res.status(404).json({ error: 'Unable to determine location' });
//     }
//   } catch (error) {
//     res.status(500).json({ error: 'API error' });
//   }
// });

// // WebSocket Connection Handling
// wss.on('connection', (ws) => {
//   console.log('Client connected');
//   ws.on('close', () => console.log('Client disconnected'));
// });
const uploadvideo = multer({
  storage: multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, 'uploads/videos/'); // Ensure this directory exists
    },
    filename: function (req, file, cb) {
      cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`);
    },
  }),
  limits: { fileSize: 100 * 1024 * 1024 }, // Max 100MB file size for videos
});

// Event Schema
const eventSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  videoUrl: { type: String, required: true },
  createdBy: { type: String, required: true }, // Admin user ID
  createdAt: { type: Date, default: Date.now },
});

const Event = mongoose.model('Event', eventSchema);

// Route to create an event
app.post('/create-event', authenticateToken, async (req, res) => {
  const { title, description } = req.body;

  // Check if the user is an admin
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') {
    return res.status(403).json({ message: 'Access denied. Only admins can create events.' });
  }

  try {
    const newEvent = new Event({
      title,
      description,
      createdBy: req.user.userId, // Admin user ID
    });

    await newEvent.save();
    res.status(201).json({ message: 'Event created successfully', event: newEvent });
  } catch (error) {
    console.error('Error creating event:', error);
    res.status(500).json({ message: 'Error creating event', error: error.message });
  }
});

// Route to upload a video for an event
app.post('/upload-video/:eventId', authenticateToken, uploadvideo.single('video'), async (req, res) => {
  const { eventId } = req.params;

  // Check if the user is an admin
  if (req.user.role !== 'admin' || req.user.role == 'superadmin'&& req.user.role !== 'user') {
    return res.status(403).json({ message: 'Access denied. Only admins and super admins can upload videos.' });
  }

  try {
    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }

    // Update the event with the video URL
    const videoUrl = req.file.path; // Path to the uploaded video
    event.videoUrl = videoUrl;
    await event.save();

    res.status(200).json({ message: 'Video uploaded successfully', event });
  } catch (error) {
    console.error('Error uploading video:', error);
    res.status(500).json({ message: 'Error uploading video', error: error.message });
  }
});

// Route to get all events (Admin only)
app.get('/events', authenticateToken, async (req, res) => {
  // Check if the user is an admin
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') {
    return res.status(403).json({ message: 'Access denied. Only admins can view events.' });
  }

  try {
    const events = await Event.find().sort({ createdAt: -1 }); // Fetch all events, sorted by newest first
    res.status(200).json(events);
  } catch (error) {
    console.error('Error fetching events:', error);
    res.status(500).json({ message: 'Error fetching events', error: error.message });
  }
});


// Route to Request a Password Reset (Sends Reset Link to Email)
app.post('/reset-password-request', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const resetToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Request',
      html: `
      <div style="background-color: #f8f9fa; padding: 30px; border-radius: 12px; margin: 20px auto; max-width: 650px; box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1); font-family: 'Arial', sans-serif;">
        <h2 style="color: #2c3e50; text-align: center; font-weight: 700; font-size: 28px; margin-bottom: 20px;">Geo Tree App - Password Reset Request</h2>
        <p style="color: #7f8c8d; text-align: center; font-size: 16px; line-height: 1.5;">We received a request to reset the password for your Geo Tree App account. If you made this request, please click the link below to create a new password. If you did not request this change, you can safely ignore this email.</p>
        <div style="text-align: center; margin-top: 30px;">
          <a href="${resetLink}" style="background-color: #3498db; color: #fff; padding: 12px 30px; text-decoration: none; font-size: 18px; border-radius: 6px; font-weight: bold; transition: background-color 0.3s ease-in-out;">Reset My Password</a>
        </div>
        <hr style="border-top: 1px solid #ecf0f1; width: 100%; margin: 30px 0; border-radius: 8px;">
        <p style="color: #7f8c8d; text-align: center; font-size: 16px;">If you need any assistance or have questions, feel free to reach out to our support team:</p>
        <div style="text-align: center; margin-top: 20px;">
          <p style="color: #7f8c8d; font-size: 16px; margin: 5px 0;">Geo Tree App<br>Powered by GPSPL</p>
          <p><a href="mailto:info@gpspl.com" style="color: #3498db; text-decoration: none; font-weight: bold;">info@gpspl.com</a></p>
          <p><a href="https://www.gpspl.com" style="color: #3498db; text-decoration: none; font-weight: bold;">www.gpspl.com</a></p>
        </div>
      </div>`
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Password reset email sent' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Something went wrong' });
  }
});

// Route to Reset the Password
app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (newPassword.length < 6 || !/[A-Z]/.test(newPassword) || !/\d/.test(newPassword)) {
      return res.status(400).json({ message: 'Password must be at least 6 characters long, contain at least one uppercase letter, and one number' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.status(200).json({ message: 'Password has been reset successfully' });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(400).json({ message: 'Reset token has expired' });
    } else if (err.name === 'JsonWebTokenError') {
      return res.status(400).json({ message: 'Invalid reset token' });
    }
    console.error(err);
    res.status(500).json({ message: 'Something went wrong' });
  }
});

// Passport Google Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ email: profile.emails[0].value });
        if (!user) {
          const hashedPassword = await bcrypt.hash(profile.id, 10); // Generate random password
          user = new User({
            firstName: profile.name.givenName || 'Unknown',
            lastName: profile.name.familyName || 'Unknown',
            email: profile.emails[0].value,
            password: hashedPassword,
            userId: profile.id,
          });
          await user.save();
        }
        done(null, user);
      } catch (err) {
        console.error('Error in Google Strategy:', err);
        done(err, null);
      }
    }
  )
);

// Serialize and Deserialize User
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Routes for Google Authentication
app.get('/google-login', (req, res) => {
  res.send('<h1>Welcome</h1><a href="/auth/google">Login with Google</a>');
});

app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
  })
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    if (!req.user) {
      return res.redirect('/');
    }
    const token = generateToken(req.user.userId, req.user.role || 'user');
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/dashboard');
  }
);

app.get('/dashboard', (req, res) => {
  if (!req.user) {
    return res.redirect('/');
  }
  res.send(`<h1>Hello, ${req.user.firstName || 'User'}</h1><a href="/logout">Logout</a>`);
});

app.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    res.clearCookie('token');
    res.redirect('/');
  });
});

// Error Handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on http://127.0.0.1:${PORT}`));
