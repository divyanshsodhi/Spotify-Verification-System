const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const userModel= require('./models/userModel')

const app = express();


app.set('view engine','ejs');
app.use(express.urlencoded({extended:true}));
// Middleware
app.use(express.json());
app.use(cookieParser());



// User Schema and Model


// Secret key for JWT
const jwtSecret = process.env.SECRET;

// Middleware to verify JWT from cookies
function authenticateToken(req, res, next) {
  const token = req.cookies.token; // Extract token from cookies
  if (!token) {
    return res.status(401).send('Access denied'); // No token provided
  }

  try {
    const verified = jwt.verify(token, jwtSecret); // Verify the token
    req.user = verified; // Attach decoded payload (e.g., email) to the request
    next(); // Proceed to the next middleware or route
  } catch (err) {
    res.status(403).send('Invalid token'); // Token verification failed
  }
}

app.get('/',(req,res)=>{
  res.render('main');
})

app.get('/signup',(req,res)=>{
  res.render('signup');
})
app.get('/login',(req,res)=>{
  res.render('login');
})
// Route: User Registration
app.post('/create', async (req, res) => {
  const { email, phone, password } = req.body;

  try {
    // Check if the user already exists
    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res.status(400).send('User already registered with this email');
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create the user
    const user = await userModel.create({
      email,
      phone,
      password: hashedPassword,
    });

    // Sign a JWT token for the user using email
    const token = jwt.sign({ email: user.email }, jwtSecret);

    // Store the token in a cookie
    res.cookie('token', token);

    res.json({ message: 'User created successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).send('Error creating user');
  }
});

// Route: User Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user by email
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(400).send('Invalid email or password');
    }

    // Compare the provided password with the hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).send('Invalid email or password');
    }

    // Sign a JWT token for the user using email
    const token = jwt.sign({ email: user.email }, jwtSecret);

    // Store the token in a cookie
    res.cookie('token', token);

    res.json({ message: 'Login successful' });
  } catch (error) {
    console.error(error);
    res.status(500).send('Error logging in');
  }
});

// Protected Routes
app.get('/profile', authenticateToken, (req, res) => {
  res.send(`Welcome to your profile, user with email: ${req.user.email}`);
});

// Start the server
app.listen(process.env_PORT);
