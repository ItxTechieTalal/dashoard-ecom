import express from "express";
import connectToMongo from "./config/db.js";
import userModel from "./schema/schema.js";
import productModel from './config/product.js'
import jwt from 'jsonwebtoken'
import cors from "cors";
const PORT = 5000;
const app = express();  
connectToMongo();
app.use(cors()); 
app.use(express.json());
 

const jwtKey = 'myEcomSite'
app.post("/register", async (req, res) => {
  // Check if a user with the same email already exists
  const existingUser = await userModel.findOne({ email: req.body.email });

  if (existingUser) {
    // User with the same email already exists, send a response
    res.status(400).send({ message: 'User already signed up' });
  } else {
    // Create and save the new user
    const newUser = new userModel(req.body);
    try {
      const result = await newUser.save();
      const sanitizedResult = { ...result.toObject() };
      delete sanitizedResult.password;
       
      jwt.sign({sanitizedResult},jwtKey,{expiresIn:'2h'}, (err,token)=>{
        res.send({sanitizedResult , auth : token})})
    } catch (error) {
      console.error('Error:', error);
      res.status(500).send({ message: 'Server error' });
    }
  }
});

app.post("/login", async (req, res) => {
  if (req.body.email && req.body.password) {
    let user = await userModel.findOne({ email: req.body.email }).select('-password');

    if (user) {
      jwt.sign({user},jwtKey,{expiresIn:'2h'}, (err,token)=>{
        res.send({user , auth : token});
if(err){
  res.status(401).send({ message: 'Something is wrong' });

}
      })
    } else {
      res.status(401).send({ message: 'Unauthorized: User not found or invalid credentials' });
    }
  } else {
    res.status(400).send({ message: 'Bad Request: Missing email or password' });
  }
}); 


app.post("/add-product"  ,async(req,res)=>{
let product = new productModel(req.body)
let result =  await product.save()
res.send(result)
})

app.get('/product',  async(req ,res)=>{
const allProducts = await productModel.find()
res.send(allProducts) 
console.log(allProducts);
})   

  
app.delete('/product/:id'  ,verifyToken, async(req,res)=>{
const Products = await productModel.deleteOne({_id : req.params.id})
res.send(Products)
})
app.get('/product/:id', async(req,res)=>{
const Products = await productModel.findOne({_id : req.params.id})
res.send(Products)
})
app.put('/product/:id', async(req,res)=>{
const Products = await productModel.updateOne({_id : req.params.id},{$set:req.body})
res.send(Products)
})

//search data
app.get('/search/:key', verifyToken, async(req,res)=>{
  const Products = await productModel.find({
    '$or' : [
      {
        name : {$regex:req.params.key},
      

      },
      {
      
        company : {$regex:req.params.key},

      },
      {
      
        category : {$regex:req.params.key},

      },
    ]
  })
  res.send(Products)
  })

 
function  verifyToken(req,res,next){
  let token = req.headers['authorization']
  if (token) {
    // token = token.split(' ') //split on base 
  
}
    })
  } else {
  res.send({result : "please add token with header"})
    
  }
next()
}


 
 
app.listen(PORT);
 of space
     token = token.split(' ')[1] //split on base of space
    console.warn('middleware agya ha' , token);
    jwt.verify(token,jwtKey,(err ,success)=>{
if (err) {
  res.status(401).send({result : "please provide valid token"})
  
} else {