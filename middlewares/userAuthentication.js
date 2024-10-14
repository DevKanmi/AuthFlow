import { StatusCodes } from "http-status-codes";
import { validToken } from "../utils/Auth.js";
import { errorResponse, successResponse } from "../utils/responses.js";
import ApiError from './errorHandler/api-error.js'

export const tokenAuthentication = async(req, res, next) =>{
    const authHeader = req.headers['authorization']

    if(!authHeader) return ApiError.badRequest(`No Token Was found!`)
    
    if(authHeader.startsWith('Bearer ')){
        const token = authHeader.replace('Bearer ','')
        
    try{
        const payload = validToken(token)
        if(!validToken) return ApiError.badRequest(`Token is Invalid`)
        req.user = {id: payload.id}
        next()
    }

    catch(error){
        next(error)
    }

    }
    

}