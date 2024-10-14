export const successResponse = (res,statusCode, message, data) =>{
    return res.status(statusCode).send({
        status : 'Success',
        message: message,
        data

    })
}

export const errorResponse = (res, statusCode, error) =>{
    return res.status(statusCode).send({
        status: 'Failed/Error',
        error
    })
}