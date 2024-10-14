import express from "express";

export const userRouter = express.Router()

import { registerUser, verifyOTP, userLogin, changePassword,forgotPassword, resetPassword } from "../controllers/userAuth.js";

import { tokenAuthentication } from "../middlewares/userAuthentication.js";

userRouter.post('/signup', registerUser)
userRouter.post('/verify-otp', verifyOTP)
userRouter.post('/login', userLogin)
userRouter.post('/change-password',tokenAuthentication, changePassword)
userRouter.post('/forgot-password',forgotPassword)
userRouter.post('/reset-password/:resetToken', resetPassword)

