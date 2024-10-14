import ApiError from "./errorHandler/api-error.js";


export const Notfound = (req,res,next) =>{
    next(ApiError.notFound())
}