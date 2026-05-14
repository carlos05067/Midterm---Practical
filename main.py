import os
from typing import Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, status
from sqlmodel import SQLModel, Field, create_engine, Session, select
from pydantic import BaseModel
from passlib.context import CryptContext
import uvicorn

PEPPER = os.getenv("SECRET_PEPPER", "configurar_pepper_en_archivo_env")

contexto_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

engine = create_engine(
    "sqlite:///./users.db",
    connect_args={"check_same_thread": False}
)

class Usuario(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    nombre_usuario: str = Field(unique=True, index=True)
    contrasena_hash: str
    creado_en: datetime = Field(default_factory=datetime.utcnow)

class UsuarioRegistro(BaseModel):
    nombre_usuario: str
    contrasena: str

class UsuarioLogin(BaseModel):
    nombre_usuario: str
    contrasena: str

class UsuarioRespuesta(BaseModel):
    id: int
    nombre_usuario: str
    creado_en: datetime

class Autenticacion(BaseModel):
    message: str
    user: UsuarioRespuesta

def hashear_contrasena(contrasena: str) -> str:
    return contexto_pwd.hash(contrasena + PEPPER)

def verificar_contrasena(contrasena_plana: str, contrasena_hasheada: str) -> bool:
    return contexto_pwd.verify(contrasena_plana + PEPPER, contrasena_hasheada)

app = FastAPI(title="API de Autenticación")

@app.on_event("startup")
def startup():
    SQLModel.metadata.create_all(engine)

@app.post("/register", response_model=UsuarioRespuesta, status_code=status.HTTP_201_CREATED)
def register(datos: UsuarioRegistro):
    with Session(engine) as sesion:
        if sesion.exec(select(Usuario).where(Usuario.nombre_usuario == datos.nombre_usuario)).first():
            raise HTTPException(status_code=400, detail="El usuario ya existe")

        usuario = Usuario(
            nombre_usuario=datos.nombre_usuario,
            contrasena_hash=hashear_contrasena(datos.contrasena)
        )
        sesion.add(usuario)
        sesion.commit()
        sesion.refresh(usuario)

        return UsuarioRespuesta(id=usuario.id, nombre_usuario=usuario.nombre_usuario, creado_en=usuario.creado_en)

@app.post("/login", response_model=Autenticacion)
def login(datos: UsuarioLogin):
    with Session(engine) as sesion:
        usuario = sesion.exec(select(Usuario).where(Usuario.nombre_usuario == datos.nombre_usuario)).first()

        if not usuario or not verificar_contrasena(datos.contrasena, usuario.contrasena_hash):
            raise HTTPException(status_code=401, detail="Credenciales inválidas")

        return Autenticacion(
            message="Autenticación exitosa",
            user=UsuarioRespuesta(id=usuario.id, nombre_usuario=usuario.nombre_usuario, creado_en=usuario.creado_en)
        )

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
