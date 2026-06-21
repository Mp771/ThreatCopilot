from fastapi import APIRouter, HTTPException
from app.schemas.auth import RegisterRequest, LoginRequest
from app.auth.password import hash_password, verify_password
from app.auth.jwt_handler import create_access_token
from app.db.postgres import get_connection

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register")
def register(data: RegisterRequest):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id FROM users
        WHERE username=%s OR email=%s
        """,
        (data.username, data.email)
    )

    if cur.fetchone():
        raise HTTPException(
            status_code=400,
            detail="User already exists"
        )

    hashed = hash_password(data.password)

    cur.execute(
        """
        INSERT INTO users
        (username,email,password_hash)
        VALUES (%s,%s,%s)
        """,
        (
            data.username,
            data.email,
            hashed
        )
    )

    conn.commit()

    cur.close()
    conn.close()

    return {
        "message": "User created"
    }


@router.post("/login")
def login(data: LoginRequest):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, username, password_hash
        FROM users
        WHERE username=%s
        """,
        (data.username,)
    )

    user = cur.fetchone()

    cur.close()
    conn.close()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    if not verify_password(
        data.password,
        user[2]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    token = create_access_token({
        "sub": user[1],
        "user_id": user[0]
    })

    return {
        "access_token": token,
        "token_type": "bearer"
    }