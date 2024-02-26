const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt'); // For password hashing

const app = express();
app.use(bodyParser.json());
app.use(cors());

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'chatgpt'
});

// Route for handling user registration
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10); // 10 is the saltRounds

  // Insert user credentials into the database
  connection.query(
    'INSERT INTO users (email, password) VALUES (?, ?)',
    [email, hashedPassword],
    (error, results) => {
      if (error) {
        console.error('Error inserting user:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
      }

      console.log('User inserted successfully:', results);
      res.status(200).json({ message: 'User registered successfully' });
    }
  );
});

// Route for handling login requests
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  console.log('Received login request for email:', email);

  // Fetch user from the database based on the provided email
  connection.query(
    'SELECT * FROM users WHERE email = ?',
    [email],
    async (error, results) => {
      if (error) {
        console.error('Error fetching user:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
      }

      console.log('User fetched from the database:', results);

      // Check if the user exists
      if (results.length === 0) {
        console.log('User not found');
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Compare the provided password with the hashed password from the database
      const user = results[0];
      const passwordMatch = await bcrypt.compare(password, user.password);

      console.log('Password match result:', passwordMatch);

      if (passwordMatch) {
        // Passwords match, login successful
        console.log('Login successful');
        res.status(200).json({ message: 'Login successful' });
      } else {
        // Passwords don't match, login failed
        console.log('Login failed');
        res.status(401).json({ error: 'Invalid credentials' });
      }
    }
  );
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {  
  console.log(`Server is running on port ${PORT}`);
});