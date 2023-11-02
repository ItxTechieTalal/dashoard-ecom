import express from "express";
import connectToMongo from "./config/db.js";
import userModel from "./schema/schema.js";
// import productModel from "./schema/schema.js" // Assuming your product schema is in the "schema" folder
import jwt from 'jsonwebtoken';
import cors from "cors";

const PORT = 5000;
const app = express();

connectToMongo();

app.use(cors());
app.use(express.json());

const jwtKey = 'myEcomSite';

app.post("/register", async (req, res) => {
  try {
    // Check if a user with the same email already exists
    const existingUser = await userModel.findOne({ email: req.body.email });

    if (existingUser) {
      // User with the same email already exists, send a response
      return res.status(400).json({ message: 'User already signed up' });
    }

    // Create and save the new user
    const newUser = new userModel(req.body);
    const result = await newUser.save();
    const sanitizedResult = { ...result.toObject() };
    delete sanitizedResult.password;

    jwt.sign({ sanitizedResult }, jwtKey, { expiresIn: '2h' }, (err, token) => {
      if (err) {
        return res.status(500).json({ message: 'Error creating token' });
      }
      res.json({ sanitizedResult, auth: token });
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post("/login", async (req, res) => {
  try {
    if (req.body.email && req.body.password) {
      const user = await userModel.findOne({ email: req.body.email }).select('-password');

      if (user) {
        jwt.sign({ user }, jwtKey, { expiresIn: '2h' }, (err, token) => {
          if (err) {
            return res.status(401).json({ message: 'Something is wrong' });
          }
          res.json({ user, auth: token });
        });
      } else {
        res.status(401).json({ message: 'Unauthorized: User not found or invalid credentials' });
      }
    } else {
      res.status(400).json({ message: 'Bad Request: Missing email or password' });
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post("/add-product", async (req, res) => {
  try {
    const product = new productModel(req.body);
    const result = await product.save();
    res.json(result);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/product', async (req, res) => {
  try {
    const allProducts = await productModel.find();
    res.json(allProducts);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/product/:id', verifyToken, async (req, res) => {
  try {
    const result = await productModel.deleteOne({ _id: req.params.id });
    res.json(result);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/product/:id', async (req, res) => {
  try {
    const product = await productModel.findOne({ _id: req.params.id });
    res.json(product);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/product/:id', async (req, res) => {
  try {
    const result = await productModel.updateOne({ _id: req.params.id }, { $set: req.body });
    res.json(result);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Search data
app.get('/search/:key', verifyToken, async (req, res) => {
  try {
    const products = await productModel.find({
      $or: [
        { name: { $regex: req.params.key, $options: 'i' } }, // Case-insensitive search
        { company: { $regex: req.params.key, $options: 'i' } },
        { category: { $regex: req.params.key, $options: 'i' } },
      ]
    });
    res.json(products);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

function verifyToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ result: 'Please add a token with the header' });
  }

  const tokenParts = token.split(' ');
  if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
    return res.status(401).json({ result: 'Invalid token format' });
  }

  const tokenValue = tokenParts[1];
  jwt.verify(tokenValue, jwtKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ result: 'Please provide a valid token' });
    }
    next();
  });
}

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
