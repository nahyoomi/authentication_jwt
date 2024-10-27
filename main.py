from fastapi import FastAPI, Request, Form, HTTPException, Cookie
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from typing import Annotated
from datetime import datetime, timedelta
from jose import JWTError, jwt

SECRET_KEY = "86cba7318717c1dd9451c4338b072fa23b2873c4e7066a066d0c462c179c964f"
TOKEN_EXPIRE_SECONDS = 20
db_users = {
    "nahomi":
    {
        "id": 1,
        "username": "nahomi",
        "password": "nahomi123"
    },
    "Johnnatan":
    {  
        "id": 2,
        "username": "Johnnatan",
        "password": "123456#hash"
    }
}

app = FastAPI()
jinja2_template = Jinja2Templates(directory="templates")

def get_user(username: str, db_users: dict):
    if username in db_users:
        return db_users[username]
    
def authenticate_user(password: str, password_plain: str):
    password_clean = password.split("#")[0]
    if password_plain == password_clean:
        return True
    return False

def create_token(data: dict):
    data_token = data.copy()
    data_token["exp"] = datetime.utcnow() + timedelta(seconds=TOKEN_EXPIRE_SECONDS)
    token_jwt = jwt.encode(data_token, key=SECRET_KEY, algorithm="HS256")   
    return token_jwt

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    return jinja2_template.TemplateResponse("index.html", {"request": request})

@app.get("/users/dashboard")
def dashboard(request: Request, access_token: Annotated[str | None, Cookie()]):
    if access_token is None:
        return RedirectResponse("/", status_code=302)
    try:
        data_user = jwt.decode(access_token, key=SECRET_KEY, algorithms=["HS256"])
        if get_user(data_user["username"], db_users) is None:
            return RedirectResponse("/", status_code=302)
        return jinja2_template.TemplateResponse("dashboard.html", {"request": request})
    except JWTError:
        return RedirectResponse("/", status_code=302)

@app.post("/users/login")
def login(username: Annotated[str, Form(...)], password: Annotated[str, Form(...)]):
    user_data = get_user(username, db_users)
    if user_data is None:
        raise HTTPException(status_code=401, detail="NO authorization")
    if not authenticate_user(user_data["password"], password):
        raise HTTPException(status_code=401, detail="NO authorization for user or password")     
    token = create_token({"username": user_data["username"]})
    response = RedirectResponse("/users/dashboard", status_code=302)
    response.set_cookie(key="access_token", value=token, max_age=TOKEN_EXPIRE_SECONDS)
    return response

@app.post("/users/logout")
def logout():
    response = RedirectResponse("/", status_code=302, headers={
        "set-cookie": "access_token=; Max-Age=0"
    })
    response.delete_cookie(key="access_token")
    return response