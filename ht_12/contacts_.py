import os.path
import sys
import time

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from src.database.database_ import get_db
from src.routes import contacts, auth


app = FastAPI()


@app.middleware("http")
async def custom_middleware(request: Request, call_next):
    start = time.time()
    try:
        response = await call_next(request)
    except SQLAlchemyError as error:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": str(error)})
    duration = time.time() - start
    response.headers["performance"] = str(duration)
    return response


@app.get("/")
async def root():
    return {"message": "Here your contacts!"}


@app.get("/api/healthchecker")
def healthchecker(db: Session = Depends(get_db)):
    try:
        result = db.execute(text("SELECT 1")).fetchone()
        if not result:
            raise HTTPException(status_code=500, detail="Database is not configured correctly")
        return {"message": "Welcome to FastAPI"}
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Error connecting to yhe database")


app.include_router(contacts.router, prefix="/api")
app.include_router(auth.router, prefix="/api")


if __name__ == '__main__':
    uvicorn.run("contacts_:app", reload=True)
