import mongoose,{ Schema} from "mongoose";

const userSchema = new Schema({
    username: {
        type: String,
        required: true
    },
    name: String,
    email: String,
    password: String,
    isVerified:{
        type: Boolean,
        default: false
    },
    otp: {
        type: String
    },
    otpexpiresat: {
        type: Date
    },
    resettoken :{
        type: String
    },
    resettokenexpires: {
        type: Date
    }
})

userSchema.set('toJSON', {
    transform: (document, returnedObject) =>{
        returnedObject.id = returnedObject._id.toString()
        delete returnedObject._id
        delete returnedObject.__v
        delete returnedObject.otp
        delete returnedObject.otpexpiresat
        delete returnedObject.password
      }
})

const User = mongoose.model('User', userSchema)

export default User