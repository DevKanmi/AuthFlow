import { config } from "dotenv";

config();

export const PORT = process.env.PORT
export const EMAIL_USER = process.env.EMAIL_USER
export const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD
export const JWT_SECRET = process.env.JWT_SECRET
export const jwt_lifetime = process.env.JWT_LIFETIME