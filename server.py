from typing import Optional
import  json

import base64
import hmac
import hashlib
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response

app = FastAPI()

MY_KEY = "7d98ajd27d7g9vsj29v7c"
PASSWORD_SALT = "8f03jr8dj3273ry24"


def secure_data(data: str) -> str:
    return hmac.new(
        MY_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def username_from_secure_username(secure_username: str) -> Optional[str]:
    if "." not in secure_username:
        return None
    username_base64, sign = secure_username.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = secure_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"]
    return password_hash == stored_password_hash


users = {
    "megadrochila": {
        "name": "Дрочила",
        "password": "b228b72a621a0ff99063eac983436dcbee33286cbdcb887c59b517d7d9987cfe",
        "fisting": "300.01$"
    },
        "superdrochila": {
            "name": "Drochila",
            "password": "dd5aeaebb6cbd34cef93cfb9b6a00622b3c6980918824b0076bf859c2572dbb0",
            "fisting": "300$"
        },



}


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('temp/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = username_from_secure_username(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(f"Hello, {users[valid_username]['name']}", media_type="text/html")


@app.post("/login")
def process_login_page(username: str = Form(...), password: str = Form(...)):

    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "massage": "Failed log in"
            }), media_type="application/json")
    response = Response(
        json.dumps({
            "success": True,
            "message": f"hello {user['name']}!<br /> Fisting price {user['fisting']}"
        }),
        media_type="application/json")
    username_secure = base64.b64encode(username.encode()).decode() + "." + secure_data(username)
    response.set_cookie(key="username", value=username_secure)
    return response
