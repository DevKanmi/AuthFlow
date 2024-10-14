import { config } from "dotenv";
import nodemailer from 'nodemailer'
import { EMAIL_USER, EMAIL_PASSWORD } from "../envVariables.js";



const transport = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user : EMAIL_USER,
        pass: EMAIL_PASSWORD
    },
    debug: true,
    logger: true
})

export const sendMail = async(email,subjecthead,content ) =>{
const mailOptions = {
    from : EMAIL_USER,
    to: email,
    subject: subjecthead,
    html: content
}

await transport.sendMail(mailOptions)

}
