import mongoose  from "mongoose";
const productSchema = mongoose.Schema({
 name : {
  type : String
 },
 price: {
  type : String
 },
category  : {
  type : String
 },
 userID  : {
  type : String
 },
 company  : {
  type : String
 },
})

const productModel = mongoose.model("products", productSchema)
export default productModel