# main.py
from fastapi import FastAPI, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import date
from decimal import Decimal # Importar Decimal para manejar tipos Numeric
from sqlalchemy.exc import IntegrityError
from sqlalchemy import case
import traceback

# Importar func y literal_column para cálculos de SQLAlchemy
from sqlalchemy import func, literal_column, asc, desc # Importar asc y desc para ordenar

# >>>>>> AÑADE ESTA LÍNEA <<<<<<
from pydantic import BaseModel # <--- ¡IMPORTA BaseModel aquí!
# >>>>>> FIN DE LA LÍNEA <<<<<<

# Importar para hashing de contraseñas
import hashlib


from passlib.context import CryptContext

from app import models, schemas, database

# Importar CORS
from fastapi.middleware.cors import CORSMiddleware # <--- Añadir esta línea

from app.schemas import VentaDetalleOut

from app.routers import dni

from sqlalchemy import exists

# from .auth import get_current_user

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

import requests
import os

app.include_router(dni.router)




# Función para hashear una contraseña
#def get_password_hash(password: str) -> str:
#    return pwd_context.hash(password)

def get_password_hash_2(password):
    return pwd_context.hash(password)

def verify_password_2(password, hashed):
    try:
        return pwd_context.verify(password, hashed)
    except Exception as e:
        print(f"Error al verificar contraseña: {e}")
        return False

def get_password_hash(password: str) -> str:
    # Pre-hash SHA256
    sha = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return pwd_context.hash(sha)

# Función para verificar una contraseña hasheada
# def verify_password(plain_password: str, hashed_password: str) -> bool:
#    return pwd_context.verify(plain_password, hashed_password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    sha = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
    return pwd_context.verify(sha, hashed_password)

# Configuración de CORS para permitir que tu frontend React acceda al backend
# Ajusta el "http://localhost:3000" a la URL donde se ejecuta tu aplicación React
origins = [
     "http://localhost:3000",  # La URL de tu aplicación React
     "http://localhost:3001",  # La URL de tu aplicación React
     "http://127.0.0.1:3000",
     "http://127.0.0.1:3001",
     "https://appventasfront.onrender.com" # React en producción
     # Puedes añadir otras URLs si tu frontend se ejecuta en otros dominios/puertos
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Permite todos los métodos (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],  # Permite todos los encabezados
)

# Dependency
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Crear todas las tablas si no existen (solo para desarrollo/pruebas)
# @app.on_event("startup")
# def on_startup():
#    models.Base.metadata.create_all(bind=database.engine)

# --- Dependencia para obtener el usuario logeado (simulado por ahora) ---
# En un sistema real, esto se obtendría del JWT token.
# Por ahora, simularemos que el user_id (UUID) del usuario logeado se pasa como un header.
async def get_current_user(
    user_id_header: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> models.User:
    if user_id_header is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User-Id-Header es requerido")
    try:
        # Esta línea es crucial: busca por el campo 'usuario'
        user = db.query(models.User).filter(models.User.id == user_id_header).first()
        print(models.User.usuario)
        print(user_id_header)
        if user is None:
            # El 404 se lanza aquí si el usuario no es encontrado por el 'usuario' en el DB
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
        return user
    except Exception as e:
        # Aquí se capturarían otros errores, pero el 404 es explícito arriba
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Error en User-Id-Header: {e}")
        
# Endpoint de Login (adaptado para usar SQLAlchemy)
@app.post("/login", response_model=schemas.User)
async def login_user(login_data: schemas.LoginRequest, db: Session = Depends(database.get_db)):
    # Buscar usuario por email o nombre de usuario
    user = db.query(models.User).filter(
        (models.User.email == login_data.email_or_username) |
        (models.User.usuario == login_data.email_or_username)
    ).first()

    # Validar que el usuario existe y que la contraseña es correcta
    if not user or not verify_password(login_data.password, user.clave):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")

    # En un escenario real, aquí se generaría un token JWT para la sesión
    # return {"message": "Login exitoso", "user_id": str(user.id)}
    return user

# --- Endpoints CRUD de Usuarios ---

@app.post("/users/", response_model=schemas.User, status_code=status.HTTP_201_CREATED)
async def create_user(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    """Crea un nuevo usuario con la clave hasheada."""
    # Verificar si el email o usuario ya existen
    try:
        #db_user_email = db.query(models.User).filter(models.User.email == user.email).first()
        #if db_user_email:
        #    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El email ya está registrado")
        
        db_user_username = db.query(models.User).filter(models.User.usuario == user.usuario).first()
        if db_user_username:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El nombre de usuario ya está en uso")

        # Hashear la contraseña antes de guardar
        hashed_password = get_password_hash(user.clave)
        # db_user = models.User(**user.model_dump(exclude={"clave"}), clave=hashed_password)
        db_user = models.User(
            apel_pat=user.apel_pat[:30],
            apel_mat=user.apel_mat[:30],
            nombres=user.nombres[:50],
            email=user.email[:100],
            telefono=user.telefono[:20] if user.telefono else None,
            usuario=user.usuario[:10],
            tipo=user.tipo[:1],
            promo=user.promo[:4] if user.promo else None,
            clave=hashed_password
        )
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail="Error de integridad en la base de datos: posiblemente email o usuario duplicado")
    except Exception as e:
        db.rollback()
        # Log interno para debugging
        print("Error creando usuario:", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Error interno al crear el usuario")

@app.get("/users/", response_model=List[schemas.User])
async def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db)):
    """Obtiene la lista de todos los usuarios."""
    users = db.query(models.User).offset(skip).limit(limit).all()
    return users

@app.get("/users/{user_id}", response_model=schemas.User)
async def read_user(user_id: int, db: Session = Depends(database.get_db)):
    """Obtiene un usuario específico por su ID."""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
    return user

@app.put("/users/{user_id}", response_model=schemas.User)
async def update_user(user_id: int, user_update: schemas.UserUpdate, db: Session = Depends(database.get_db)):
    """Actualiza la información de un usuario existente, hasheando la nueva clave si se proporciona."""
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")

    update_data = user_update.model_dump(exclude_unset=True)

    # Verificar conflictos de email o usuario con otros usuarios
    #if "email" in update_data and update_data["email"] != db_user.email:
    #    existing_email_user = db.query(models.User).filter(models.User.email == update_data["email"]).first()
    #    if existing_email_user and existing_email_user.id != user_id:
    #        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El nuevo email ya está registrado por otro usuario")
    
    if "usuario" in update_data and update_data["usuario"] != db_user.usuario:
        existing_username_user = db.query(models.User).filter(models.User.usuario == update_data["usuario"]).first()
        if existing_username_user and existing_username_user.id != user_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El nuevo nombre de usuario ya está en uso por otro usuario")

    # Hashear la nueva contraseña si se proporciona
    if "clave" in update_data and update_data["clave"]:
        update_data["clave"] = get_password_hash(update_data["clave"])
    
    for key, value in update_data.items():
        setattr(db_user, key, value)
    
    db.commit()
    db.refresh(db_user)
    return db_user

@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: int, db: Session = Depends(database.get_db)):
    """Elimina un usuario por su ID."""
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
    
    has_payments = db.query(
        exists().where(models.Sale.usuario == db_user.usuario)
        ).scalar()

    if has_payments:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No se puede eliminar usuario, ha realizado ventas"
        )
    
    db.delete(db_user)
    db.commit()
    return {"message": "Usuario eliminado exitosamente"}

# --- Nuevos Endpoints CRUD para Ventas  ---

@app.post("/sales/", response_model=schemas.Sale, status_code=status.HTTP_201_CREATED)
async def create_sale(
    sale: schemas.SaleCreate,
    current_user: models.User = Depends(get_current_user), # Obtener el usuario logeado
    db: Session = Depends(database.get_db)
):
     
    sale_exist = db.query(models.Sale).filter(
        models.Sale.dni == sale.dni
    ).first()

    if sale_exist:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El DNI ya se encuentra registrado"
        )
    
    # Calcular importe y total
    calculated_importe =  sale.precio_unitario
    calculated_total = sale.cantidad * calculated_importe 

    db_sale = models.Sale(
        dni=sale.dni,
        nombres=sale.nombres,
        fecha=sale.fecha,
        cantidad=sale.cantidad,
        importe=calculated_importe,
        total=calculated_total,
        ticket=sale.ticket,
        celular=sale.celular,
        # usuario=current_user.usuario,  Usuario que realiza la venta 
        usuario = current_user.usuario,
        vendedor_username_fk=current_user.usuario, # Asigna el nombre de usuario a la clave foránea
        promo=current_user.promo       # Promoción del usuario que realiza la venta
    )
    db.add(db_sale)
    db.commit()
    db.refresh(db_sale)
    return db_sale

@app.get("/sales/", response_model=List[schemas.Sale])
async def read_sales(
    current_user: models.User = Depends(get_current_user),
    skip: int = 0, limit: int = 100,
    db: Session = Depends(database.get_db)
):
    # Opcional: filtrar ventas por el usuario logeado
    sales = db.query(models.Sale).filter(models.Sale.vendedor_username_fk == current_user.usuario).offset(skip).limit(limit).all()
    return sales

@app.get("/sales/{sale_id}", response_model=schemas.Sale)
async def read_sale(
    sale_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    sale = db.query(models.Sale).filter(
        models.Sale.id == sale_id,
        models.Sale.vendedor_username_fk == current_user.usuario # Corregido: Usar vendedor_username_fk
    ).first()
    if sale is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Venta no encontrada o no pertenece al usuario autenticado")
    return sale

@app.put("/sales/{sale_id}", response_model=schemas.Sale)
async def update_sale(
    sale_id: int,
    sale_update: schemas.SaleUpdate, # <--- ¡Cambiado a SaleUpdate!
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    db_sale = db.query(models.Sale).filter(
        models.Sale.id == sale_id,
        models.Sale.vendedor_username_fk == current_user.usuario
    ).first()
    if db_sale is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Venta no encontrada o no pertenece al usuario autenticado")

    update_data = sale_update.model_dump(exclude_unset=True)

    # Recalcular importe y total si cantidad o precio_unitario cambian
    if "cantidad" in update_data or "precio_unitario" in update_data:
        new_cantidad = update_data.get("cantidad", db_sale.cantidad)
        
        # Obtener el nuevo precio_unitario si se proporcionó, o calcularlo del importe existente
        # Si db_sale.cantidad es 0, usamos 0 para evitar división por cero.
        current_precio_unitario = db_sale.importe / db_sale.cantidad if db_sale.cantidad > 0 else 0
        new_precio_unitario = update_data.get("precio_unitario", current_precio_unitario)
        
        calculated_importe = new_cantidad * new_precio_unitario
        update_data["importe"] = new_precio_unitario
        update_data["total"] = calculated_importe # Recalculate total as well

    # No permitir que el usuario o promo se actualicen desde el frontend
    update_data.pop("usuario", None) 
    update_data.pop("promo", None)
    
    for key, value in update_data.items():
        setattr(db_sale, key, value)
    
    db.commit()
    db.refresh(db_sale)
    return db_sale


@app.delete("/sales/{sale_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sale(sale_id: int, db: Session = Depends(database.get_db)):
    """Elimina un usuario por su ID."""
    db_sale = db.query(models.Sale).filter(models.Sale.id == sale_id).first()
    if db_sale is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Venta no encontrado")
    
    has_payments = db.query(
        exists().where(models.Payment.dni == db_sale.dni)
        ).scalar()

    if has_payments:
        raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="No se puede eliminar la venta porque tiene pagos registrados"
    )
    
    db.delete(db_sale)
    db.commit()
    return {"message": "Venta eliminado exitosamente"}
# --- Nuevos Endpoints CRUD para Pagos  ---

# Esquema para la respuesta de saldo
class BalanceResponse(BaseModel):
    dni: str
    nombres: Optional[str] # Nombre del cliente, si lo obtenemos de una venta
    ticket: Optional[str] # Tipo del cliente, si lo obtenemos de una venta o del usuario logeado
    total_compras: float
    total_pagos: float
    saldo_pendiente: float

@app.get("/payments/balance/{dni}", response_model=BalanceResponse)
async def get_client_balance(
    dni: str,
    current_user: models.User = Depends(get_current_user), # No se usa current_user directamente para filtrar aquí, pero se mantiene para autenticación
    db: Session = Depends(get_db)
):
    # Suma de ventas por DNI
    total_sales_result = db.query(func.sum(models.Sale.total)).filter(
        models.Sale.dni == dni
    ).scalar()
    total_compras = float(total_sales_result) if total_sales_result else 0.0

    # Suma de pagos por DNI
    total_payments_result = db.query(func.sum(models.Payment.pago)).filter(
        models.Payment.dni == dni
    ).scalar()
    total_pagos = float(total_payments_result) if total_payments_result else 0.0

    saldo_pendiente = total_compras - total_pagos

    # Intentar obtener el nombre del cliente de alguna venta para mostrarlo
    client_name_result = db.query(models.Sale.nombres).filter(models.Sale.dni == dni).first()
    client_name = client_name_result.nombres if client_name_result else None

    client_ticket_result = db.query(models.Sale.ticket).filter(models.Sale.dni == dni).first()
    client_ticket = client_ticket_result.ticket if client_ticket_result else None

    return BalanceResponse(
        dni=dni,
        nombres=client_name,
        ticket=client_ticket,
        total_compras=total_compras,
        total_pagos=total_pagos,
        saldo_pendiente=saldo_pendiente
    )


@app.post("/payments/", response_model=schemas.Payment, status_code=status.HTTP_201_CREATED)
async def create_payment(
    payment: schemas.PaymentCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_payment = models.Payment(
        dni=payment.dni,
        fecha=payment.fecha,
        pago=payment.pago,
        tipo=payment.tipo,
        det_tipo=payment.det_tipo,
        registrador_username_fk=current_user.usuario,
        promo=current_user.promo
    )
    db.add(db_payment)
    db.commit()
    db.refresh(db_payment)
    return db_payment

@app.get("/payments/",  response_model=list[schemas.PaymentOut])
async def read_payments(
    current_user: models.User = Depends(get_current_user),
    skip: int = 0, limit: int = 100,
    db: Session = Depends(get_db)
):
    # Traer todos los pagos registrados por el usuario actual
    # payments = db.query(models.Payment).filter(models.Payment.registrador_username_fk == current_user.usuario).offset(skip).limit(limit).all()

    payments = (
        db.query(
            models.Payment.id,
            models.Payment.dni,
            models.Sale.nombres,
            models.Sale.ticket,
            models.Payment.fecha,
            models.Payment.pago,
            models.Payment.tipo,
            models.Payment.det_tipo,
            models.Payment.promo
        )
        .outerjoin(models.Sale, models.Payment.dni == models.Sale.dni)
        .filter(models.Payment.registrador_username_fk == current_user.usuario)
        .offset(skip)
        .limit(limit)
        .all()
    )   
    return payments

@app.get("/payments/{payment_id}", response_model=schemas.Payment)
async def read_payment(
    payment_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    payment = db.query(models.Payment).filter(
        models.Payment.id == payment_id,
        models.Payment.registrador_username_fk == current_user.usuario
    ).first()
    if payment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pago no encontrado o no pertenece al usuario autenticado")
    return payment

@app.put("/payments/{payment_id}", response_model=schemas.Payment)
async def update_payment(
    payment_id: int,
    payment_update: schemas.PaymentUpdate, # Usamos PaymentUpdate
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_payment = db.query(models.Payment).filter(
        models.Payment.id == payment_id,
        models.Payment.registrador_username_fk == current_user.usuario
    ).first()
    if db_payment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pago no encontrado o no pertenece al usuario autenticado")

    update_data = payment_update.model_dump(exclude_unset=True)
    update_data.pop("usuario", None)
    update_data.pop("promo", None)

    for key, value in update_data.items():
        setattr(db_payment, key, value)
    
    db.commit()
    db.refresh(db_payment)
    return db_payment


@app.delete("/payments/{payment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_payment(
    payment_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_payment = db.query(models.Payment).filter(
        models.Payment.id == payment_id,
        models.Payment.registrador_username_fk == current_user.usuario
    ).first()
    if db_payment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pago no encontrado o no pertenece al usuario autenticado")
    
    db.delete(db_payment)
    db.commit()
    return {"message": "Pago eliminado exitosamente"}


# --- NUEVO ENDPOINT: CONSULTA DE ESTADO DE CUENTA ---

@app.get("/account-statement/{dni}", response_model=schemas.ClientAccountStatement)
async def get_account_statement(
    dni: str,
    current_user: models.User = Depends(get_current_user), # Asegura que el usuario esté autenticado
    db: Session = Depends(get_db)
):

    user_tipo = int(current_user.tipo)
    user_promo = current_user.promo
    # user_dni = current_user.dni   # si existe

    # TIPO 3 → USUARIO
    if user_tipo == 3:
        cliente = db.query(models.Sale).filter(models.Sale.dni == dni).first()
        if not cliente:
            raise HTTPException(
                    status_code=403,
                    detail="No tiene permiso para consultar este DNI"
                )

    # TIPO 2 → PROMOTOR
    if user_tipo == 2:
        cliente = db.query(models.Sale).filter(models.Sale.dni == dni).first()
        if not cliente or cliente.promo != user_promo:
            raise HTTPException(
                    status_code=403,
                    detail="El cliente no pertenece a su promoción"
                 )
    
    # 1. Obtener información del cliente (nombre, promoción)
    client_info = db.query(models.Sale.nombres, models.User.promo)\
                    .join(models.User, models.Sale.vendedor_username_fk == models.User.usuario)\
                    .filter(models.Sale.dni == dni)\
                    .first()
    
    nombres_cliente = client_info.nombres if client_info and client_info.nombres else None
    # Podría ser mejor obtener la promoción del usuario actual, o del usuario que registró la última transacción
    # Por ahora, se puede dejar en None o buscar de la tabla Sale/Payment si se guardó ahí.
    # Si la promoción es del cliente (no del vendedor), necesitaríamos una tabla de Clientes.
    # Por simplicidad, obtenemos la promoción del User que registró la primera venta encontrada.
    promocion_cliente = client_info.promo if client_info and client_info.promo else None


    # 2. Obtener todas las ventas y pagos para el DNI dado
    sales = db.query(models.Sale).filter(models.Sale.dni == dni).all()
    payments = db.query(models.Payment).filter(models.Payment.dni == dni).all()

    transactions = []
    for sale in sales:
        transactions.append({
            "fecha": sale.fecha,
            "descripcion": f"Compra de {sale.cantidad} entradas (ID: {sale.id})",
            "tipo_transaccion": "Compra",
            "monto": sale.total,
            "saldo_acumulado": Decimal('0.00') # Se calculará después
        })
    
    for payment in payments:
        transactions.append({
            "fecha": payment.fecha,
            "descripcion": f"Pago (ID: {payment.id}, Tipo: {payment.tipo})",
            "tipo_transaccion": "Pago",
            "monto": payment.pago,
            "saldo_acumulado": Decimal('0.00') # Se calculará después
        })

    # 3. Ordenar las transacciones por fecha (y luego por tipo si las fechas son iguales, ej. compras antes que pagos)
    transactions.sort(key=lambda x: (x["fecha"], x["tipo_transaccion"]))

    # 4. Calcular el saldo acumulado
    saldo_actual = Decimal('0.00')
    processed_transactions = []
    for t in transactions:
        if t["tipo_transaccion"] == "Compra":
            saldo_actual += t["monto"]
        elif t["tipo_transaccion"] == "Pago":
            saldo_actual -= t["monto"]
        
        t["saldo_acumulado"] = saldo_actual
        processed_transactions.append(schemas.StatementTransaction(**t)) # Convertir a Pydantic

    return schemas.ClientAccountStatement(
        dni=dni,
        nombres_cliente=nombres_cliente,
        promocion_cliente=promocion_cliente,
        transacciones=processed_transactions,
        saldo_final=saldo_actual
    )


@app.get("/ConsultaVentas/", response_model=list[schemas.VentaDetalleOut])
def get_consulta_ventas(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
  
    resu_subq = (
        db.query(
            models.Sale.dni.label("dni"),
            models.Sale.nombres.label("nombres"),
            models.Sale.ticket.label("ticket"),
            func.sum(models.Sale.cantidad).label("cantidad"),
            func.sum(models.Sale.total).label("total"),
        )
        .group_by(models.Sale.dni, models.Sale.nombres, models.Sale.ticket)
        .subquery()
    )

    pagos_subq = (
        db.query(func.sum(models.Payment.pago))
        .filter(models.Payment.dni == resu_subq.c.dni)
        .correlate(resu_subq)
        .scalar_subquery()
    )

    query = (
        db.query(
            resu_subq.c.dni,
            resu_subq.c.nombres,
            resu_subq.c.ticket,
            resu_subq.c.cantidad,
            resu_subq.c.total,
            func.coalesce(pagos_subq, 0).label("pagos"),
            (resu_subq.c.total-func.coalesce(pagos_subq, 0)).label("saldo"),
        )
    )

    return query.all()


@app.get("/PromoVentas/{promo}", response_model=list[schemas.VentaDetalleOut])
def get_consulta_ventas(
    promo: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    
    user_tipo = int(current_user.tipo)
    user_promo = current_user.promo

       # TIPO 2 → PROMOTOR
    if user_tipo == 2:
        if promo != user_promo:
            raise HTTPException(
                    status_code=403,
                    detail="El Promotor no pertenece a esta promoción"
                 )
 
    resu_subq = (

    db.query(
            models.Sale.dni.label("dni"),
            models.Sale.promo.label("promo"),
            models.Sale.nombres.label("nombres"),
            models.Sale.ticket.label("ticket"),
            func.sum(models.Sale.cantidad).label("cantidad"),
            func.sum(models.Sale.total).label("total"),
        )
        .group_by(models.Sale.dni, models.Sale.promo, models.Sale.nombres, models.Sale.ticket)
        .subquery()
    )

    pagos_subq = (
        db.query(func.sum(models.Payment.pago))
        .filter(models.Payment.dni == resu_subq.c.dni)
        .correlate(resu_subq)
        .scalar_subquery()
    )

    query = (
        db.query(
            resu_subq.c.dni,
            resu_subq.c.nombres,
            resu_subq.c.ticket,
            resu_subq.c.cantidad,
            func.coalesce(resu_subq.c.total,0).label("total"),
            func.coalesce(pagos_subq, 0).label("pagos"),
            (func.coalesce(resu_subq.c.total,0)-func.coalesce(pagos_subq, 0)).label("saldo"),
        ).filter(resu_subq.c.promo == promo)
    )

    return query.all()


@app.get("/ResumenVentas/", response_model=list[schemas.ResumenVentasOut])
def get_consulta_ventas(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    subq = (
            db.query(
                    models.Sale.promo.label("promo"),
                    func.sum(models.Sale.cantidad).label("cantidad"),
                    func.sum(models.Sale.total).label("total"),
                    )
            .group_by(models.Sale.promo)
            .subquery()
            )

    pagos_subq = (
            db.query(func.sum(models.Payment.pago))
                .filter(models.Payment.promo == subq.c.promo)
                .correlate(subq)
                .scalar_subquery()
        )

    query = (
        db.query(
            subq.c.promo,
            subq.c.cantidad,
            func.coalesce(subq.c.total,0).label("total"),
            func.coalesce(pagos_subq,0).label("pagos"),
            (func.coalesce(subq.c.total,0)-func.coalesce(pagos_subq,0)).label("saldo"),
        )
    )
    return query.all()


# Esquema para la respuesta de saldo
class LiquidaResponse(BaseModel):
    usuario_lq: str
    promo:str
    nombres: Optional[str] # Nombre del cliente, si lo obtenemos de una venta
    total_ventas: float
    total_pagos: float
    saldo_pendiente: float
    total_cobros: float

@app.get("/liquida/balance/{usuario_lq}", response_model=LiquidaResponse)
async def get_client_liquida(
    usuario_lq: str,
    current_user: models.User = Depends(get_current_user), # No se usa current_user directamente para filtrar aquí, pero se mantiene para autenticación
    db: Session = Depends(get_db)
):
    print("LIQUIDA RECIBIDA 2:", usuario_lq)

    # Suma de ventas por DNI
    total_sales_result = db.query(func.sum(models.Sale.total)).filter(
        models.Sale.usuario== usuario_lq
    ).scalar()
    total_ventas = float(total_sales_result) if total_sales_result else 0.0

    # Suma de pagos por promotor
    total_liquida_result = db.query(func.sum(models.Liquida.pago)).filter(
        models.Liquida.usuario_lq == usuario_lq
    ).scalar()
    total_pagos = float(total_liquida_result) if total_liquida_result else 0.0

    # Suma de pagos por usuario
    total_payments_result = db.query(func.sum(models.Payment.pago)).filter(
        models.Payment.registrador_username_fk == usuario_lq
    ).scalar()
    total_cobra = float(total_payments_result) if total_payments_result else 0.0

    saldo_pendiente = total_ventas - total_pagos

    # Intentar obtener el nombre del cliente de alguna venta para mostrarlo
    client_promo_result = db.query(models.User.promo ).filter(models.User.usuario == usuario_lq).first()
    client_promo = client_promo_result.promo if client_promo_result else "None"

    client_name_result = db.query(func.concat(models.User.nombres , ' ', models.User.apel_pat , ' ', models.User.apel_mat).label("nombre")).filter(models.User.usuario == usuario_lq).first()
    client_name = client_name_result.nombre if client_name_result else None

    return LiquidaResponse(
        usuario_lq=usuario_lq,
        promo=client_promo,
        nombres=client_name,
        total_ventas=total_ventas,
        total_pagos=total_pagos,
        saldo_pendiente=saldo_pendiente,
        total_cobros=total_cobra
    )


@app.post("/liquida/", response_model=schemas.Liquida, status_code=status.HTTP_201_CREATED)
async def create_liquida(
    liquida: schemas.LiquidaCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    print("LIQUIDA RECIBIDA 1:", liquida.usuario_lq)

    db_liquida = models.Liquida(
        usuario_lq=liquida.usuario_lq,
        promo=liquida.promo,
        fecha=liquida.fecha,
        pago=liquida.pago,
        tipo=liquida.tipo,
        det_tipo=liquida.det_tipo,
        registrador_username_fk=current_user.usuario
    )
    db.add(db_liquida)
    db.commit()
    db.refresh(db_liquida)
    return db_liquida

@app.get("/liquida/", response_model=List[schemas.LiquidaOut])
async def read_liquida(
    current_user: models.User = Depends(get_current_user),
    skip: int = 0, limit: int = 100,
    db: Session = Depends(get_db)
):
    # Traer todos los pagos registrados por el usuario actual
    liquidas = (
                db.query(
                          models.Liquida.usuario_lq,
                          func.concat(
                             models.User.nombres, ' ',
                             models.User.apel_pat, ' ',
                             models.User.apel_mat
                          ).label("nombres"),
                          models.Liquida.promo,
                          models.Liquida.fecha,
                          models.Liquida.pago,
                          models.Liquida.tipo,
                          models.Liquida.det_tipo
                        )
                    .outerjoin(models.User, models.Liquida.usuario_lq == models.User.usuario)
                    .all()
                )
    return liquidas
    #liquidas = db.query(models.Liquida).filter(models.Liquida.registrador_username_fk == current_user.usuario).offset(skip).limit(limit).all()
    

@app.get("/liquida/{liquida_id}", response_model=schemas.Liquida)
async def read_liquida(
    liquida_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    payment = db.query(models.Liquida).filter(
        models.Liquida.id == liquida_id,
        models.Liquida.registrador_username_fk == current_user.usuario
    ).first()
    if payment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pago no encontrado o no pertenece al usuario autenticado")
    return payment

@app.put("/liquida/{liquida_id}", response_model=schemas.Liquida)
async def update_liquida(
    liquida_id: int,
    liquida_update: schemas.LiquidaUpdate, # Usamos LiquidaUpdate
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_liquida = db.query(models.Liquida).filter(
        models.Liquida.id == liquida_id,
        models.Liquida.registrador_username_fk == current_user.usuario
    ).first()
    if db_liquida is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pago no encontrado o no pertenece al usuario autenticado")

    update_data = liquida_update.model_dump(exclude_unset=True)
    update_data.pop("usuario", None)
    update_data.pop("promo", None)

    for key, value in update_data.items():
        setattr(db_liquida, key, value)

    db.commit()
    db.refresh(db_liquida)
    return db_liquida


@app.delete("/liquida/{liquida_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_payment(
    liquida_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_liquida = db.query(models.Liquida).filter(
        models.Liquida.id == liquida_id,
        models.Liquida.registrador_username_fk == current_user.usuario
    ).first()
    if db_liquida is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pago no encontrado o no pertenece al usuario autenticado")
    
    db.delete(db_liquida)
    db.commit()
    return {"message": "Pago eliminado exitosamente"}

@app.get("/promoters/", response_model=list[schemas.PromoterOut])
def get_promoters(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    promoters = db.query(
        models.User.id,
        func.concat(models.User.nombres , ' ', models.User.apel_pat , ' ', models.User.apel_mat).label("nombres"),
        models.User.usuario,
        models.User.promo
    ).filter(
        models.User.tipo == "2"
    ).all()

    return promoters


# --- NUEVO ENDPOINT: CONSULTA DE ESTADO DE CUENTA ---

@app.get("/ConsultaLiq/{usuario_lq}", response_model=schemas.ClientAccountStatement)
async def get_account_statement(
    usuario_lq: str,
    current_user: models.User = Depends(get_current_user), # Asegura que el usuario esté autenticado
    db: Session = Depends(get_db)
):

    user_tipo = int(current_user.tipo)

    if user_tipo != 1:
       raise HTTPException(
             status_code=403,
             detail="No tiene permiso para esta consulta"
       )

    
    # 1. Obtener información del cliente (nombre, promoción)
    client_info = db.query( func.concat(
                             models.User.nombres, ' ',
                             models.User.apel_pat, ' ',
                             models.User.apel_mat
                            ).label("nombres"),
                            models.User.promo,)\
                    .filter(models.User.usuario == usuario_lq)\
                    .first()
    
    nombres_cliente = client_info.nombres if client_info and client_info.nombres else None
    # Podría ser mejor obtener la promoción del usuario actual, o del usuario que registró la última transacción
    # Por ahora, se puede dejar en None o buscar de la tabla Sale/Payment si se guardó ahí.
    # Si la promoción es del cliente (no del vendedor), necesitaríamos una tabla de Clientes.
    # Por simplicidad, obtenemos la promoción del User que registró la primera venta encontrada.
    promocion_cliente = client_info.promo if client_info and client_info.promo else None


    # 2. Obtener todas las ventas y pagos para el usuario dado
    #sales = db.query(models.Sale).filter(models.Sale.vendedor_username_fk == usuario_lq).all()

    sales =db.query(
            func.sum(models.Sale.cantidad).label("cantidad"),
            func.sum(models.Sale.total).label("total")
            ).filter(models.Sale.usuario == usuario_lq).group_by(models.Sale.usuario).first()  

    safec =db.query(models.Sale.fecha).filter(models.Sale.usuario == usuario_lq).order_by(models.Sale.fecha.asc()).first()
    
    payments = db.query(models.Liquida).filter(models.Liquida.usuario_lq == usuario_lq).all()

    cantidad = sales.cantidad if sales else 0
    total = sales.total if sales else 0

    transactions = []
    #for sale in sales:
    transactions.append({
        "fecha": safec.fecha if safec else date.today(),
        "descripcion": f"Separación de asistencia {cantidad} ",
        "tipo_transaccion": "Separación",
        "monto": total,
        "saldo_acumulado": Decimal('0.00') # Se calculará después
    })
    
    for payment in payments:
        tipo_pago_texto = case(
            (payment.tipo == "E", "Efectivo"),
            (payment.tipo == "T", "Tarjeta"),
            (payment.tipo == "P", "Plin"),
            (payment.tipo == "Y", "Yape"),
            (payment.tipo == "R", "Transferencia"),
            else_="Desconocido"
        ).label("tipo_texto")
        tipo_texto = db.query(tipo_pago_texto).filter(models.Liquida.id == payment.id).first()[0]
        
        transactions.append({
            "fecha": payment.fecha,
            "descripcion": f"Pago (Tipo: {tipo_texto})",
            "tipo_transaccion": "Pago",
            "monto": payment.pago,
            "saldo_acumulado": Decimal('0.00') # Se calculará después
        })

    # 3. Ordenar las transacciones por fecha (y luego por tipo si las fechas son iguales, ej. compras antes que pagos)
    transactions.sort(key=lambda x: (x["fecha"], x["tipo_transaccion"]))

    # 4. Calcular el saldo acumulado
    saldo_actual = Decimal('0.00')
    processed_transactions = []
    for t in transactions:
        if t["tipo_transaccion"] == "Separación":
            saldo_actual += t["monto"]
        elif t["tipo_transaccion"] == "Pago":
            saldo_actual -= t["monto"]
        
        t["saldo_acumulado"] = saldo_actual
        processed_transactions.append(schemas.StatementTransaction(**t)) # Convertir a Pydantic

    return schemas.PromotoresAccountStatement(
        dni="",
        usuario_lq=usuario_lq,
        nombres_cliente=nombres_cliente,
        promocion_cliente=promocion_cliente,
        saldo_final=float(saldo_actual),
        transacciones=processed_transactions
    )


