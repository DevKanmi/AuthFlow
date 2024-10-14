//Import packages
import { StatusCodes } from "http-status-codes";
import bcrypt from 'bcrypt'
import crypto from 'crypto'


//Import files
import logger from "../utils/logger.js";
import { successResponse, errorResponse } from "../utils/responses.js";
import { hashPassword, verifyPassword, otp, sendOTPVerificationEmail, createtoken, sendResetEmail} from "../utils/Auth.js";

//Import Models
import User from "../models/userSchema.js";
import { error } from "console";


export const registerUser = async(req, res, next) =>{
    const { username, name, email, password} = req.body
    try{
        logger.info(`START: User Creation has Started`)
        if(username === password){
            logger.info(`END: username and password are similiar`)
            return errorResponse(res, StatusCodes.BAD_REQUEST, `Username and Password Can't be the same!`)
        }
        const existingUser = await User.findOne({ $or: [{ username }, { email }] })

        if(existingUser){
            logger.info(`END: username and email are present in DB, expected Unique Details!`)
            return errorResponse(res, StatusCodes.BAD_REQUEST,`Username/Email has been taken, try with another Username!`)
        }
        const otpgen = otp.generateOTP()
        const expires = otp.otpExpiration()

        const newUser = await User.create({
            name,
            username,
            email,
            password: await hashPassword(password),
            otp: await bcrypt.hash(otpgen, 10),
            otpexpiresat: expires
     })

    await sendOTPVerificationEmail(newUser.username, newUser.email,otpgen)

    logger.info(`END: User Created Successully, Kindly Verify your Email!`)
    return successResponse(res, StatusCodes.CREATED,'User Created Sucessfully', newUser)

    }
    catch(error){
        logger.info(`END: User Registration was not Successful, Passed to ErrorHandler`)
        console.log(error)
        next(error)
    }
}


export const verifyOTP = async(req, res, next) =>{
    const {email, otp} = req.body

    try{
        const user = await User.findOne({email})

        if(user.isVerified) return errorResponse(res, StatusCodes.BAD_REQUEST, 'Email is already Verified')

        if (!user) {
            return errorResponse(res, StatusCodes.BAD_REQUEST, 'User not found');
        }
        
        const otpVer = bcrypt.compare(otp, user.otp)

        if (!otpVer || Date.now() > user.otpexpiresat) {
            return errorResponse(res, StatusCodes.BAD_REQUEST, 'Invalid or expired OTP');
        }

        user.isVerified = true
        user.otp = null
        user.otpexpiresat = null
        await user.save()

        return successResponse(res, StatusCodes.OK, 'Email verified successfully');

    }    

    catch(error){
        console.log(error)
        next(error)
    }
}

export const userLogin = async(req, res, next) =>{
    const {username, password} = req.body
    if(!username || !password) return errorResponse(res, StatusCodes.NOT_FOUND, `Username and Password is Required`)

    try{
        logger.info(`START: Attempting to Login`)

        const user = await User.findOne({username})
        if(!user) return errorResponse(res, StatusCodes.NOT_FOUND, `Username does not exist Please Create an account`)
        
        const isPasswordCorrect = await verifyPassword(password, user.password)
        
        if(!isPasswordCorrect){
                logger.info(`END: Login Attempt was unsuccessful`)
                return errorResponse(res, StatusCodes.NOT_FOUND, `Incorrect Password! Try again!`)
        }

        if(!user.isVerified){
            logger.info(`END: User has not been Verified, Kindly try again!`)
            return errorResponse(res, StatusCodes.BAD_REQUEST, `User has not been Verified`)

        }
        const accessToken = createtoken(user._id)
        logger.info(`END: Logged In Successfully`)
        return successResponse(res, StatusCodes.OK, {user, accessToken})
        
    }
    catch(error){
        console.log(error)
        next(error)
    }
}

export const changePassword = async(req, res, next) =>{
    //If a user is logged IN, the user can request to change his paasword
    const userId = req.user.id
    const{ currentpassword , newpassword, confirmnewpassword} = req.body

    if(!currentpassword || !newpassword || !confirmnewpassword){
        return errorResponse(res, StatusCodes.NOT_FOUND, `Can\'t leave fields empty!`)
    }

    try{
        logger.info(`START: Attempting changing of password`)
        const user = await User.findById(userId)
        if(!user){
            return errorResponse(res,StatusCodes.UNAUTHORIZED, 'Only logged in Users can Change their password, Please click on the forget password if you can\'t remember your password!');
        }

        const correctPassword = await verifyPassword(currentpassword, user.password)

        if(!correctPassword){
            return errorResponse(res, StatusCodes.BAD_REQUEST, 'current Password is not correct try again')
        }

        if(newpassword === currentpassword){
            return errorResponse(res, StatusCodes.BAD_REQUEST, `Old password can\'t be the same as the new password`)
        }

        if(newpassword !== confirmnewpassword){
            return errorResponse(res, StatusCodes.BAD_REQUEST, `Please kindly ensure confirm password is entered correctly`)
        }

        user.password = await hashPassword(newpassword)
        await user.save()

        logger.info(`END: Password was successfully changed`)
        successResponse(res, StatusCodes.OK, `Password successfully changed`, user)

    }
    catch(error){
        next(error)
    }
}


export const forgotPassword = async(req, res, next) => {
    const {email} = req.body
    if(!email){
        return errorResponse(res, StatusCodes.NOT_FOUND, `Email is required`)
    }

    try{
        logger.info(`START: Attempting to send Password Reset Link`)
        const user = await User.findOne({email})
        if(!user){
            return errorResponse(res, StatusCodes.NOT_FOUND, `Account does not exist, Kindly Register`)
        }

        const resetToken = crypto.randomBytes(20).toString('hex') 
        const resetUrl = `${req.protocol}://${req.get('host')}/api/users/reset-password/${resetToken}`;

        await sendResetEmail(user.username, user.email, resetUrl)

        user.resettoken = crypto.createHash('sha256').update(resetToken).digest('hex')
        user.resettokenexpires = Date.now() + 10 * 60 * 1000 // Expiration of 10mins
        await user.save()

        logger.info(`END: Password Reset Link sent Successfully`)

        successResponse(res, StatusCodes.OK, `Reset Link Successfully sent to mail!`)

    }
    catch(error){
        next(error)
    }
}




export const resetPassword = async(req, res, next) =>{

    //The user is not logged in, can't remember password we want to send a reset link to the email, here a new password is entered and saved
    //From the forgot password endpoint we get a reset password link to perform any action

    const resetToken = req.params.resetToken
    const {newpassword, confirmnewpassword} = req.body

    try{
            logger.info(`START: Attempting Resetting Password`)
            const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex')
            const user = await User.findOne({
                resettoken: hashedToken,
                resettokenexpires: { $gt : Date.now() }
            })

            if(!user){
                return errorResponse(res, StatusCodes.BAD_REQUEST, `Token is Invalid or has Expired.`)
            }

            if(newpassword !== confirmnewpassword){
                return errorResponse(res, StatusCodes.BAD_REQUEST,`Passwords Do not match!`)
            }

            user.password = await hashPassword(newpassword)
            user.resettoken = null
            user.resettokenexpires = null

            await user.save()
            logger.info(`END: Password reset was Successfull`)
            return successResponse(res, StatusCodes.OK, `Password reset was successfull, Kindly log in!`)
    }
    catch(error){
        logger.error(error)
        next(error)
    }
}