from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt

app = FastAPI(title="Smart Recycling Auth & Profile API")

# تفعيل الـ CORS عشان الواجهات تقدر تكلم السيرفر
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# إعدادات تشفير كلمات المرور باستخدام Passlib
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# إعدادات الـ JWT Token (مفتاح سرى مؤقت للمشروع)
SECRET_KEY = "smart_recycling_secret_key_2026"
ALGORITHM = "HS256"

# قاعدة بيانات مؤقتة لتخزين المستخدمين (حتى نربطها بقاعدة بيانات SQL لاحقاً)
fake_users_db = []

# نموذج بيانات التسجيل (Register)
class UserRegister(BaseModel):
    username: str
    password: str
    confirm_password: str

# نموذج بيانات تسجيل الدخول (Login)
class UserLogin(BaseModel):
    username: str
    password: str

# دالة لتشفير كلمة المرور
def get_password_hash(password: str):
    return pwd_context.hash(password)

# دالة للتحقق من تطابق كلمة المرور العادية مع المشفرة
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register_user(user: UserRegister):
    # 1. التأكد من تطابق كلمتي المرور
    if user.password != user.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="كلمتا المرور غير متطابقتين"
        )
    
    # 2. التأكد من عدم تكرار اسم المستخدم
    for existing_user in fake_users_db:
        if existing_user["username"] == user.username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="اسم المستخدم أو البريد الإلكتروني مسجل مسبقاً"
            )
    
    # 3. تشفير كلمة المرور وحفظ المستخدم
    hashed_password = get_password_hash(user.password)
    
    user_data = {
        "username": user.username,
        "password": hashed_password  # مخزنة بشكل مشفر وآمن تماماً
    }
    fake_users_db.append(user_data)
    
    return {
        "message": "تم إنشاء الحساب بنجاح وتشفير كلمة المرور",
        "username": user.username
    }


@app.post("/auth/login")
def login_user(user: UserLogin):
    # 1. البحث عن المستخدم في القائمة
    found_user = None
    for u in fake_users_db:
        if u["username"] == user.username:
            found_user = u
            break
            
    if not found_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="اسم المستخدم أو كلمة المرور غير صحيحة"
        )
    
    # 2. التحقق من صحة كلمة المرور المدخلة مقارنة بالمشفرة
    if not verify_password(user.password, found_user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="اسم المستخدم أو كلمة المرور غير صحيحة"
        )
    
    # 3. إنشاء توكين أمان (JWT Token) للمستخدم عند النجاح
    token_data = {"sub": user.username}
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    
    return {
        "message": "تم تسجيل الدخول بنجاح",
        "access_token": token,
        "token_type": "bearer"
    }


@app.get("/users")
def get_all_users():
    # للعرض فقط (مع إخفاء تفاصيل الباسورد الحساسة)
    safe_users = [{"username": u["username"]} for u in fake_users_db]
    return {"users": safe_users}