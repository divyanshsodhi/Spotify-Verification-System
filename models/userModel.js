const mongoose= require("mongoose");

mongoose.connect("mongodb://localhost:27017/Spotify-login");

const userSchema= mongoose.Schema({
   
    email:String,
    phone:Number,
    password:String
});

module.exports= mongoose.model("user",userSchema);
