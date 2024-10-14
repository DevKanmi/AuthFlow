import ApiError from "./api-error.js";
import { errorResponse } from "../../utils/responses.js";
import { StatusCodes } from "http-status-codes";
import logger from "../../utils/logger.js";

const errorHandler = (error, req, res, next) =>{
    
    //Default Message
    let message = "Request Failed, Try again Later"
    let errCode = StatusCodes.INTERNAL_SERVER_ERROR

    if(error instanceof ApiError){
        message = error.message
        errCode = error.code
    }

    else if(error instanceof Error){

        if(error.name === 'ValidationError'){
            message = error.message
            errCode = StatusCodes.UNPROCESSABLE_ENTITY
        }

        else if(error.name === 'MongoServerError'){
            if(error.errorResponse.code === 11000){
                message = "Resourca already Exists"
                errCode = StatusCodes.CONFLICT
            }
        }

        else if(error.name === 'CastError'){
            message = "Malformatted Id"
            errCode = StatusCodes.BAD_REQUEST
        }

        else if(error.name === 'JsonwebTokenError'){
            message = 'Invalid Token'
            errCode = StatusCodes.UNAUTHORIZED
        }

        else if(error.name = 'TokenExpiredError'){
            message = 'Token Has Expired, Login Again!',
            errCode = StatusCodes.UNAUTHORIZED
        }

        else if(
            error instanceof TypeError ||
            error instanceof EvalError ||
            error instanceof SyntaxError ||
            error instanceof RangeError ||
            error instanceof ReferenceError ||
            error instanceof URIError 
        ){
            message = error.message
            errCode = StatusCodes.BAD_REQUEST
        }
    }

    logger.error(`[${req.method} ${req.url}] ${typeof message === 'string' ? message : JSON.stringify(message)}`)
    errorResponse(res,errCode,message)
}

export default errorHandler