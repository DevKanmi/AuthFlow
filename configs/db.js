import mongoose from "mongoose";

import { config } from "dotenv";
config();


const MONGODB_URI = process.env.NODE_ENV === 'test'
  ? process.env.TEST_MONGODB_URI
  : process.env.MONGODB_URI

  mongoose.set('strictQuery', false)

  console.log('connecting to DB')
  
export const DBConnection = () =>{
    mongoose.connect(MONGODB_URI)
    .then(() => {
      console.log('connected to MongoDB Successfully.')
    })
    .catch((error) => {
      console.log('error connection to MongoDB:', error.message)
    })
}