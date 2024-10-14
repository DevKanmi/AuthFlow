import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import otpGenerator from 'otp-generator'
import { config } from 'dotenv'
import logger from './logger.js'

import { sendMail } from './mailer.js'
import { EMAIL_USER, EMAIL_PASSWORD, JWT_SECRET, jwt_lifetime} from "../envVariables.js";



config()


export const hashPassword = async(password) =>{
    const saltRounds = 10
    return await bcrypt.hash(password,saltRounds)
}

export const verifyPassword = async(pass1, pass2) =>{
    return await bcrypt.compare(pass1, pass2)

}


export const createtoken = (id) =>{
    const token = jwt.sign({id}, JWT_SECRET, {expiresIn: jwt_lifetime})
    return token
}

export const validToken = (token) =>{
    return jwt.verify(token, JWT_SECRET)
}


export class otp {
    static generateOTP(){
        return otpGenerator.generate(6, {lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false})
    }

    static otpExpiration(){
        return Date.now() + 10 * 60 * 1000 //Expires in 10minutes
    }
}

export const sendOTPVerificationEmail = async(username, email, otp) =>{
        try{
        
            const subject =  `Verify your Email`
            const content = `<p>Dear ${username}, </p> </br>

            <p> Kindly Enter the following code <b>${otp}</b> to Verify your email</p> </br>
            
            <p>This code expires in 10 minutes </p>`


            await sendMail(email,subject,content)

        }
    catch(error){
        console.log(error)
    }
}

export const sendResetEmail = async(username, email, url) =>{
    try{
        const subject = `Reset Password`
        const content = `<p>Dear ${username}, </p> <br>

            <p> Kindly click on the highlighted link to <a href = "${url}">Reset Password</a></p> <br>
            
            <p>This Password Reset link expires in 10 minutes </p> <br>
            
            <p> If this was not you, Ignore! </p>`
            
        await sendMail(email, subject, content)
    }
    catch(error){
        console.log(error)
    }
}

