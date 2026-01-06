# schemas.py
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import date # Importar date para el tipo fecha
from decimal import Decimal # Importar Decimal para manejar tipos Numeric de SQLAlchemy

# Esquema base para un usuario (para operaciones de lectura)
class UserBase(BaseModel):
    apel_pat: str = Field(..., max_length=30)
    apel_mat: str = Field(..., max_length=30)
    nombres: str = Field(..., max_length=50)
    email: str = Field(..., max_length=100)
    telefono: Optional[str] = Field(None, max_length=20)
    usuario: str = Field(..., max_length=10)
    tipo: str = Field(..., max_length=1)
    promo: Optional[str] = Field(None, max_length=4)

# Esquema para crear un usuario (incluye la clave)
class UserCreate(UserBase):
    # clave: str # Clave requerida para la creación
    clave: str = Field(..., min_length=5) # Añadimos validación básica de longitud

# Esquema para actualizar un usuario (todos los campos opcionales)
class UserUpdate(UserBase):
    apel_pat: Optional[str] = Field(None, max_length=30)
    apel_mat: Optional[str] = Field(None, max_length=30)
    nombres: Optional[str] = Field(None, max_length=50)
    email: Optional[str] = Field(None, max_length=100)
    telefono: Optional[str] = Field(None, max_length=20)
    usuario: Optional[str] = Field(None, max_length=10)
    tipo: Optional[str] = Field(None, max_length=1)
    clave: Optional[str] = Field(None) # La clave puede ser opcional para la actualización
    promo: Optional[str] = Field(None, max_length=4)

# Esquema completo para un usuario (incluye ID y se usa para la respuesta de la API)
class User(UserBase):
    id: int

    class Config:
        from_attributes = True # Anteriormente orm_mode = True

class LoginRequest(BaseModel):
    email_or_username: str
    password: str


# --- Nuevos Esquemas para Ventas  ---
class SaleBase(BaseModel):
    dni: str = Field(..., max_length=10)
    nombres: str = Field(..., max_length=100)
    fecha: date = Field(..., description="Fecha de la compra (YYYY-MM-DD)")
    cantidad: int = Field(..., gt=0, description="Cantidad de entradas, debe ser mayor que 0")
    
    #  precio_unitario: float = Field(..., gt=0, description="Precio por cada entrada")

class SaleCreate(SaleBase):
    # Aquí sí se espera el precio_unitario para calcular importe
    precio_unitario: float = Field(..., gt=0, description="Precio por cada entrada")

# Nuevo esquema para la actualización de ventas
class SaleUpdate(SaleBase):
    # Hacer todos los campos opcionales para la actualización parcial
    dni: Optional[str] = Field(None, max_length=10)
    nombres: Optional[str] = Field(None, max_length=100)
    fecha: Optional[date] = Field(None, description="Fecha de la compra (YYYY-MM-DD)")
    cantidad: Optional[int] = Field(None, gt=0, description="Cantidad de entradas, debe ser mayor que 0")
    precio_unitario: Optional[float] = Field(None, gt=0, description="Precio por cada entrada")

class Sale(SaleBase):
    id: int
    importe: float = Field(..., description="Importe calculado (cantidad * precio_unitario)")
    total: float = Field(..., description="Total final de la venta")
    usuario: str = Field(..., alias="vendedor_username_fk", description="Nombre de usuario del vendedor")
    promo: str = Field(..., description="Promoción del usuario vendedor")

    class Config:
        from_attributes = True
        populate_by_name = True # Necesario para que 'alias' funcione correctamente al serializar


# --- Nuevos Esquemas para Pagos  ---
class PaymentBase(BaseModel):
    dni: str = Field(..., max_length=10)
    fecha: date = Field(..., description="Fecha del pago (YYYY-MM-DD)")
    pago: float = Field(..., gt=0, description="Monto del pago, debe ser mayor que 0")
    tipo: str = Field(..., max_length=1, description="Tipo de pago (ej. 'E' efectivo, 'T' tarjeta)")
    det_tipo: Optional[str] = Field(None, max_length=50, description="Detalle del tipo de pago")

    # Los campos 'usuario' y 'promo' se obtendrán del contexto del usuario logeado.

class PaymentCreate(PaymentBase):
    pass

class PaymentUpdate(PaymentBase): # Nuevo esquema para la actualización de pagos
    dni: Optional[str] = Field(None, max_length=10)
    fecha: Optional[date] = Field(None, description="Fecha del pago (YYYY-MM-DD)")
    pago: Optional[float] = Field(None, gt=0, description="Monto del pago, debe ser mayor que 0")
    tipo: Optional[str] = Field(None, max_length=1, description="Tipo de pago (ej. 'E' efectivo, 'T' tarjeta)")
    det_tipo: Optional[str] = Field(None, max_length=50, description="Detalle del tipo de pago")

class Payment(PaymentBase):
    id: int
    # Mapeamos 'registrador_username_fk' del modelo a 'usuario' en el esquema de respuesta
    usuario: str = Field(..., alias="registrador_username_fk", description="Nombre de usuario que registró el pago")
    promo: str = Field(..., description="Promoción del usuario que registró el pago")

    class Config:
        from_attributes = True
        populate_by_name = True # Necesario para que 'alias' funcione correctamente al serializar

# Esquema para una transacción individual en el estado de cuenta
class StatementTransaction(BaseModel):
    fecha: date
    descripcion: str
    tipo_transaccion: str # "Compra" o "Pago"
    monto: Decimal # Usar Decimal para precisión monetaria
    saldo_acumulado: Decimal # Saldo después de esta transacción

    class Config:
        from_attributes = True

# Esquema para el estado de cuenta completo del cliente
class ClientAccountStatement(BaseModel):
    dni: str
    nombres_cliente: Optional[str] = None
    promocion_cliente: Optional[str] = None # Si se necesita mostrar la promoción asociada al cliente
    transacciones: List[StatementTransaction]
    saldo_final: Decimal

    class Config:
        from_attributes = True

class VentaDetalleOut(BaseModel):
    dni: str
    nombres: str
    cantidad: int
    total: Decimal
    pagos: Decimal
    saldo: Decimal

    class Config:
        from_attributes = True

class ResumenVentasOut(BaseModel):
    promo: str
    cantidad: int
    total: Decimal
    pagos: Decimal
    saldo: Decimal

    class Config:
        from_attributes = True