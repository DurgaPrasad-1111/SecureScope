from fastapi import Request
from fastapi.responses import JSONResponse
from starlette import status


class AppError(Exception):
    def __init__(self, message: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


async def app_error_handler(_: Request, exc: AppError):
    return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})


async def generic_error_handler(_: Request, __: Exception):
    return JSONResponse(status_code=500, content={'detail': 'Internal server error'})
