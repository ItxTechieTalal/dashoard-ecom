import mongoose, { connect } from "mongoose";

const connectToMongo = async()=>{
try{

const res = await mongoose.connect("mongodb+srv://mtalalrasheed127:talalhunbhai@cluster0.t9csk0a.mongodb.net/users?retryWrites=true&w=majority")
if(res){
 console.log("connected");
}
}catch(err){ 
 console.log(err);
}

}

export default connectToMongo;