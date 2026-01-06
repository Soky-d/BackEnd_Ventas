# models.py
from sqlalchemy import Column, Integer, String, Text, Date, Numeric, ForeignKey
from sqlalchemy.orm import relationship

from .database import Base

class User(Base):
    __tablename__ = "usuarios" # Nombre de la tabla según el documento 

    id = Column(Integer, primary_key=True, index=True)
    apel_pat = Column(String(30), nullable=False)
    apel_mat = Column(String(30), nullable=False)
    nombres = Column(String(50), nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    telefono = Column(String(20))
    usuario = Column(String(10), unique=True, index=True, nullable=False)
    tipo = Column(String(1), nullable=False)
    clave = Column(Text, nullable=False) # En una app real, la clave debe estar hasheada
    promo = Column(String(4))

    # Relación: Un usuario puede haber registrado muchas ventas
    # 'ventas_registradas' es el nombre de la relación en User
    # 'vendedor' es el nombre de la relación en Sale (que apunta de vuelta a User)
    ventas_registradas = relationship("Sale", back_populates="vendedor")
    
    # Relación: Un usuario puede haber registrado muchos pagos
    # 'pagos_registrados' es el nombre de la relación en User
    # 'registrador' es el nombre de la relación en Payment (que apunta de vuelta a User)
    pagos_registrados = relationship("Payment", back_populates="registrador")

    def __repr__(self):
        return f"<User(id={self.id}, nombres='{self.nombres}', email='{self.email}')>"

# Nuevo modelo para Ventas 
class Sale(Base):
    __tablename__ = "ventas"

    id = Column(Integer, primary_key=True, index=True)
    dni = Column(String(10), nullable=False)
    nombres = Column(String(100), nullable=False)
    fecha = Column(Date, nullable=False)
    cantidad = Column(Integer, nullable=False)
    importe = Column(Numeric(12,2), nullable=False) # Precio 
    total = Column(Numeric(12,2), nullable=False) # Total final, Precio * cantidad
    
    # Campo de clave foránea para el usuario que realizó la venta (el logeado)
    # Se hace referencia al campo 'usuario' de la tabla 'usuarios'
    # Cambiado de 'usuario' a 'vendedor_username_fk' para claridad y evitar conflicto con el atributo 'usuario' del modelo User
    usuario =  Column(String(10), nullable=False)
    vendedor_username_fk = Column(String(10), ForeignKey("usuarios.usuario"), nullable=False)
    promo = Column(String(4), nullable=False) # Campo de promoción del usuario que vende

    # Relación: Una venta fue registrada por un 'User'
    # 'vendedor' es el nombre de la relación en Sale
    # 'ventas_registradas' es el nombre de la relación en User (que apunta de vuelta a Sale)
    vendedor = relationship("User", back_populates="ventas_registradas")

    def __repr__(self):
        return f"<Sale(id={self.id}, dni='{self.dni}', fecha='{self.fecha}', importe='{self.importe}')>"

# Nuevo modelo para Pagos (Opcional) 
class Payment(Base):
    __tablename__ = "pagos"

    id = Column(Integer, primary_key=True, index=True)
    dni = Column(String(10), nullable=False)
    fecha = Column(Date, nullable=False)
    pago = Column(Numeric(12,2), nullable=False)
    tipo = Column(String(1), nullable=False)
    det_tipo = Column(String(50))
    
    # Campo de clave foránea para el usuario que registró el pago (el logeado)
    # Cambiado de 'usuario' a 'registrador_username_fk' para claridad y evitar conflicto con el atributo 'usuario' del modelo User
    registrador_username_fk = Column(String(10), ForeignKey("usuarios.usuario"), nullable=False)
    promo = Column(String(4), nullable=False) # Campo de promoción del usuario que registra el pago

    # Relación: Un pago fue registrado por un 'User'
    # 'registrador' es el nombre de la relación en Payment
    # 'pagos_registrados' es el nombre de la relación en User (que apunta de vuelta a Payment)
    registrador = relationship("User", back_populates="pagos_registrados")

    def __repr__(self):
        return f"<Payment(id={self.id}, dni='{self.dni}', pago='{self.pago}')>"