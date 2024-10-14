import mongoose, {Schema} from "mongoose";

const userOTPSchema = new Schema({
    userId: {
        type: Schema.Types.ObjectId,
        ref : 'User'
    },

    otp: {
        type: String,
    },

    createdAt :{
        type: Date,
        default: Date.now()
    },

    expiresAt: {
        type: Date
    }
})

userOTPSchema.set('toJSON', {
    transform: (document, returnedObject) =>{
        returnedObject.id = returnedObject._id.toString()
        delete returnedObject._id
        delete returnedObject.__v  
      }
})

const UserOTP = mongoose.model('UserOTP', userOTPSchema)
 
export default UserOTP