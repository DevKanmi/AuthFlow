import express from "express";
import { Notfound } from "./middlewares/notFound.js";
import errorHandler from "./middlewares/errorHandler/index.js";

export const app = express()

app.use(express.json())


//Import Routes here
import { userRouter } from "./routes/userAuthRoute.js";

app.use('/api/users', userRouter)

app.use(Notfound)
app.use(errorHandler)
