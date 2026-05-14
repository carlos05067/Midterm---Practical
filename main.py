import os
from typing import Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, status
from sqlmodel import SQLModel, Field, create_engine, Session, select
from pydantic import BaseModel, field_validator
from passlib.context import CryptContext
import uvicorn

PEPPER = os.getenv("SECRET_PEPPER", "configurar_pepper_en_archivo_env")

contexto_pwd = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12
)

DATABASE_URL = "sqlite:///./users.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False
)

class Usuario(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    nombre_usuario: str = Field(unique=True, index=True, min_length=3, max_length=50)
    contrasena_hash: str
    creado_en: datetime = Field(default_factory=datetime.utcnow)

    def __repr__(self):
        return f"<Usuario(id={self.id}, nombre_usuario='{self.nombre_usuario}', creado_en={self.creado_en})>"


class UsuarioRegistro(BaseModel):
    nombre_usuario: str = Field(..., min_length=3, max_length=50)
    contrasena: str = Field(..., min_length=8)

    @field_validator('nombre_usuario')
    @classmethod
    def nombre_usuario_alfanumerico(cls, v):
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('El nombre de usuario debe contener solo letras, números, guiones y guiones bajos')
        return v.lower()

    @field_validator('contrasena')
    def contrasena_fuerte(cls, v):
        if not any(c.isupper() for c in v):
            raise ValueError('Contraseña debe contener al menos una mayúscula')
        if not any(c.isdigit() for c in v):
            raise ValueError('Contraseña debe contener al menos un número')
        return v


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
    contrasena_pepper = contrasena + PEPPER
    return contexto_pwd.hash(contrasena_pepper)


def verificar_contrasena(contrasena_plana: str, contrasena_hasheada: str) -> bool:
    contrasena_pepper = contrasena_plana + PEPPER
    return contexto_pwd.verify(contrasena_pepper, contrasena_hasheada)


app = FastAPI(
    title="API de Autenticación Segura",
    description="Sistema de gestión de identidades con Hashing, Salting y Peppering",
    version="1.0.0"
)


@app.on_event("startup")
def startup():
    SQLModel.metadata.create_all(engine)
    print("Base de datos inicializada")
    print(
        f"Pepper configurado: {PEPPER[:10]}..."
        if PEPPER != "configurar_pepper_en_archivo_env"
        else "Usando pepper por defecto"
    )


@app.get("/", tags=["Info"])
def root():
    return {
        "message": "API de Autenticación Segura",
        "endpoints": {
            "register": "POST /register - Registrar nuevo usuario",
            "login": "POST /login - Autenticar usuario",
            "users": "GET /users - Listar usuarios"
        }
    }


@app.post(
    "/register",
    response_model=UsuarioRespuesta,
    status_code=status.HTTP_201_CREATED,
    tags=["Autenticación"]
)
def register(datos_usuario: UsuarioRegistro):
    with Session(engine) as sesion:
        consulta = select(Usuario).where(Usuario.nombre_usuario == datos_usuario.nombre_usuario)
        usuario_existente = sesion.exec(consulta).first()

        if usuario_existente:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El usuario ya existe"
            )

        contrasena_hasheada = hashear_contrasena(datos_usuario.contrasena)

        nuevo_usuario = Usuario(
            nombre_usuario=datos_usuario.nombre_usuario,
            contrasena_hash=contrasena_hasheada
        )

        sesion.add(nuevo_usuario)
        sesion.commit()
        sesion.refresh(nuevo_usuario)

        return UsuarioRespuesta(
            id=nuevo_usuario.id,
            nombre_usuario=nuevo_usuario.nombre_usuario,
            creado_en=nuevo_usuario.creado_en
        )


@app.post("/login", response_model=Autenticacion, tags=["Autenticación"])
def login(datos_usuario: UsuarioLogin):
    with Session(engine) as sesion:
        consulta = select(Usuario).where(Usuario.nombre_usuario == datos_usuario.nombre_usuario)
        usuario = sesion.exec(consulta).first()

        if not usuario:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas",
                headers={"WWW-Authenticate": "Bearer"}
            )

        if not verificar_contrasena(datos_usuario.contrasena, usuario.contrasena_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas",
                headers={"WWW-Authenticate": "Bearer"}
            )

        return Autenticacion(
            message="Autenticación exitosa",
            user=UsuarioRespuesta(
                id=usuario.id,
                nombre_usuario=usuario.nombre_usuario,
                creado_en=usuario.creado_en
            )
        )


@app.get("/users", response_model=list[UsuarioRespuesta], tags=["Desarrollo"])
def listar_usuarios():
    with Session(engine) as sesion:
        usuarios = sesion.exec(select(Usuario)).all()

        return [
            UsuarioRespuesta(
                id=usuario.id,
                nombre_usuario=usuario.nombre_usuario,
                creado_en=usuario.creado_en
            )
            for usuario in usuarios
        ]


@app.delete(
    "/users/{id_usuario}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Desarrollo"]
)
def delete_user(id_usuario: int):
    with Session(engine) as sesion:
        usuario = sesion.get(Usuario, id_usuario)

        if not usuario:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )

        sesion.delete(usuario)
        sesion.commit()


if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )