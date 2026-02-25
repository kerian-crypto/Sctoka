import os
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Flask, current_app, g, jsonify, request
from flask_cors import CORS
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash


db = SQLAlchemy()
migrate = Migrate()


class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(os.path.dirname(__file__), 'inventory.db')}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JSON_SORT_KEYS = False
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", SECRET_KEY)
    JWT_EXPIRES_HOURS = int(os.getenv("JWT_EXPIRES_HOURS", "24"))
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")


class Company(db.Model):
    __tablename__ = "companies"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    code = db.Column(db.String(40), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(
        db.Integer,
        db.ForeignKey("companies.id"),
        nullable=False,
        index=True,
    )
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(180), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    company = db.relationship("Company", backref=db.backref("users", lazy=True))


class Product(db.Model):
    __tablename__ = "products"

    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(
        db.Integer,
        db.ForeignKey("companies.id"),
        nullable=False,
        index=True,
    )
    name = db.Column(db.String(120), nullable=False)
    sector = db.Column(db.String(80), nullable=False)
    sku = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    low_stock_threshold = db.Column(db.Integer, nullable=False, default=50)
    purchase_price = db.Column(db.Float, nullable=False)
    sale_price = db.Column(db.Float, nullable=False)
    expiry_date = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    company = db.relationship("Company", backref=db.backref("products", lazy=True))


class StockMovement(db.Model):
    __tablename__ = "stock_movements"

    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(
        db.Integer,
        db.ForeignKey("companies.id"),
        nullable=False,
        index=True,
    )
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    movement_type = db.Column(db.String(20), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    note = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    company = db.relationship("Company", backref=db.backref("movements", lazy=True))
    product = db.relationship("Product", backref=db.backref("movements", lazy=True))


class AccountingEntry(db.Model):
    __tablename__ = "accounting_entries"

    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(
        db.Integer,
        db.ForeignKey("companies.id"),
        nullable=False,
        index=True,
    )
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    movement_id = db.Column(
        db.Integer,
        db.ForeignKey("stock_movements.id"),
        nullable=False,
    )
    entry_type = db.Column(db.String(80), nullable=False)
    debit_account = db.Column(db.String(120), nullable=False)
    credit_account = db.Column(db.String(120), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    company = db.relationship("Company", backref=db.backref("entries", lazy=True))
    product = db.relationship("Product", backref=db.backref("entries", lazy=True))
    movement = db.relationship(
        "StockMovement",
        backref=db.backref("entries", lazy=True),
    )


def user_to_dict(user: User) -> dict:
    return {
        "id": user.id,
        "company_id": user.company_id,
        "full_name": user.full_name,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat(),
    }


def product_to_dict(product: Product) -> dict:
    return {
        "id": product.id,
        "company_id": product.company_id,
        "name": product.name,
        "sector": product.sector,
        "sku": product.sku,
        "quantity": product.quantity,
        "low_stock_threshold": product.low_stock_threshold,
        "purchase_price": product.purchase_price,
        "sale_price": product.sale_price,
        "expiry_date": product.expiry_date.isoformat(),
        "created_at": product.created_at.isoformat(),
        "updated_at": product.updated_at.isoformat(),
    }


def movement_to_dict(movement: StockMovement) -> dict:
    return {
        "id": movement.id,
        "company_id": movement.company_id,
        "product_id": movement.product_id,
        "product_name": movement.product.name,
        "product_sector": movement.product.sector,
        "movement_type": movement.movement_type,
        "quantity": movement.quantity,
        "note": movement.note,
        "created_at": movement.created_at.isoformat(),
    }


def entry_to_dict(entry: AccountingEntry) -> dict:
    return {
        "id": entry.id,
        "company_id": entry.company_id,
        "product_id": entry.product_id,
        "product_name": entry.product.name,
        "movement_id": entry.movement_id,
        "entry_type": entry.entry_type,
        "debit_account": entry.debit_account,
        "credit_account": entry.credit_account,
        "amount": entry.amount,
        "created_at": entry.created_at.isoformat(),
    }


def create_token(app: Flask, user: User) -> str:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": str(user.id),
        "company_id": user.company_id,
        "role": user.role,
        "email": user.email,
        "iat": now,
        "exp": now + timedelta(hours=app.config["JWT_EXPIRES_HOURS"]),
    }
    return jwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")


def decode_token(app: Flask, token: str) -> dict:
    return jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required."}), 401

        token = header.split(" ", 1)[1].strip()
        try:
            payload = decode_token(current_app, token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token."}), 401

        user = User.query.get(int(payload["sub"]))
        if user is None or not user.is_active:
            return jsonify({"error": "User not found or inactive."}), 401

        g.user = user
        g.company_id = user.company_id
        g.role = user.role
        return fn(*args, **kwargs)

    return wrapper


def roles_required(*roles: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if g.role not in roles:
                return jsonify({"error": "Forbidden for your role."}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def company_scope() -> int:
    return g.company_id


def ensure_seed_data(app: Flask) -> None:
    if Company.query.count() == 0:
        demo_company = Company(name="Demo Market", code="DEMO")
        db.session.add(demo_company)
        db.session.commit()

    if User.query.count() == 0:
        company = Company.query.order_by(Company.id.asc()).first()
        default_email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@stocka.local")
        default_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin123!")
        default_name = os.getenv("DEFAULT_ADMIN_NAME", "Super Admin")

        admin = User(
            company_id=company.id,
            full_name=default_name,
            email=default_email.lower(),
            password_hash=generate_password_hash(default_password),
            role="admin",
            is_active=True,
        )
        db.session.add(admin)
        db.session.commit()

        app.logger.warning(
            "Default admin created: email=%s password=%s",
            default_email,
            default_password,
        )


def create_accounting_entry(
    company_id: int,
    product_id: int,
    movement_id: int,
    movement_type: str,
    amount: float,
) -> None:
    if movement_type == "in":
        debit_account = "Stock"
        credit_account = "Suppliers"
        entry_type = "Stock Purchase"
    elif movement_type == "out":
        debit_account = "Cost of Goods Sold"
        credit_account = "Stock"
        entry_type = "Stock Output"
    elif movement_type == "loss":
        debit_account = "Stock Loss"
        credit_account = "Stock"
        entry_type = "Loss"
    else:
        debit_account = "Stock"
        credit_account = "Adjustments"
        entry_type = "Adjustment"

    db.session.add(
        AccountingEntry(
            company_id=company_id,
            product_id=product_id,
            movement_id=movement_id,
            entry_type=entry_type,
            debit_account=debit_account,
            credit_account=credit_account,
            amount=round(amount, 2),
        )
    )


def register_routes(app: Flask) -> None:
    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "app": "Stocka API"})

    @app.route("/auth/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True) or {}
        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))

        if not email or not password:
            return jsonify({"error": "Email and password are required."}), 400

        user = User.query.filter_by(email=email).first()
        if user is None or not user.is_active:
            return jsonify({"error": "Invalid credentials."}), 401

        if not check_password_hash(user.password_hash, password):
            return jsonify({"error": "Invalid credentials."}), 401

        token = create_token(app, user)
        return jsonify({"token": token, "user": user_to_dict(user)})

    @app.route("/auth/me", methods=["GET"])
    @auth_required
    def me():
        return jsonify(user_to_dict(g.user))

    @app.route("/auth/users", methods=["POST"])
    @auth_required
    @roles_required("admin")
    def create_user():
        data = request.get_json(silent=True) or {}
        required = ["full_name", "email", "password", "role"]
        missing = [field for field in required if not data.get(field)]
        if missing:
            return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

        role = str(data["role"]).strip().lower()
        if role not in {"admin", "magasinier", "comptable"}:
            return jsonify({"error": "Role must be admin, magasinier, or comptable."}), 400

        email = str(data["email"]).strip().lower()
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Email already exists."}), 409

        user = User(
            company_id=company_scope(),
            full_name=str(data["full_name"]).strip(),
            email=email,
            password_hash=generate_password_hash(str(data["password"])),
            role=role,
            is_active=bool(data.get("is_active", True)),
        )
        db.session.add(user)
        db.session.commit()

        return jsonify(user_to_dict(user)), 201

    @app.route("/auth/users", methods=["GET"])
    @auth_required
    @roles_required("admin")
    def list_users():
        users = (
            User.query.filter_by(company_id=company_scope())
            .order_by(User.created_at.desc())
            .all()
        )
        return jsonify([user_to_dict(user) for user in users])

    @app.route("/auth/users/<int:user_id>", methods=["PUT"])
    @auth_required
    @roles_required("admin")
    def update_user(user_id: int):
        data = request.get_json(silent=True) or {}
        user = User.query.filter_by(id=user_id, company_id=company_scope()).first()
        if user is None:
            return jsonify({"error": "User not found."}), 404

        if "full_name" in data:
            user.full_name = str(data["full_name"]).strip()

        if "email" in data:
            email = str(data["email"]).strip().lower()
            existing = User.query.filter_by(email=email).first()
            if existing and existing.id != user.id:
                return jsonify({"error": "Email already exists."}), 409
            user.email = email

        if "role" in data:
            role = str(data["role"]).strip().lower()
            if role not in {"admin", "magasinier", "comptable"}:
                return jsonify(
                    {"error": "Role must be admin, magasinier, or comptable."}
                ), 400
            user.role = role

        if "is_active" in data:
            is_active = bool(data["is_active"])
            if user.id == g.user.id and not is_active:
                return jsonify(
                    {"error": "You cannot deactivate your own account."}
                ), 400
            user.is_active = is_active

        if "password" in data and str(data["password"]).strip():
            user.password_hash = generate_password_hash(str(data["password"]))

        db.session.commit()
        return jsonify(user_to_dict(user))

    @app.route("/auth/users/<int:user_id>", methods=["DELETE"])
    @auth_required
    @roles_required("admin")
    def delete_user(user_id: int):
        user = User.query.filter_by(id=user_id, company_id=company_scope()).first()
        if user is None:
            return jsonify({"error": "User not found."}), 404
        if user.id == g.user.id:
            return jsonify({"error": "You cannot delete your own account."}), 400

        db.session.delete(user)
        db.session.commit()
        return jsonify({"status": "deleted"})

    @app.route("/companies", methods=["GET"])
    @auth_required
    def list_companies():
        company = Company.query.get(company_scope())
        return jsonify(
            [
                {
                    "id": company.id,
                    "name": company.name,
                    "code": company.code,
                    "created_at": company.created_at.isoformat(),
                }
            ]
        )

    @app.route("/products", methods=["GET"])
    @auth_required
    def list_products():
        rows = (
            Product.query.filter_by(company_id=company_scope())
            .order_by(Product.expiry_date.asc(), Product.name.asc())
            .all()
        )
        return jsonify([product_to_dict(p) for p in rows])

    @app.route("/products", methods=["POST"])
    @auth_required
    @roles_required("admin", "magasinier")
    def create_product():
        data = request.get_json(silent=True) or {}
        required = [
            "name",
            "sector",
            "sku",
            "quantity",
            "purchase_price",
            "sale_price",
            "expiry_date",
        ]
        missing = [key for key in required if key not in data]
        if missing:
            return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

        sku = str(data["sku"]).strip()
        sku_exists = Product.query.filter_by(
            company_id=company_scope(),
            sku=sku,
        ).first()
        if sku_exists:
            return jsonify({"error": "SKU already used in this company."}), 409

        try:
            expiry_date = datetime.fromisoformat(str(data["expiry_date"]))
            quantity = int(data["quantity"])
            low_stock_threshold = int(data.get("low_stock_threshold", 50))
            purchase_price = float(data["purchase_price"])
            sale_price = float(data["sale_price"])
        except ValueError:
            return jsonify({"error": "Invalid numeric/date values."}), 400

        product = Product(
            company_id=company_scope(),
            name=str(data["name"]).strip(),
            sector=str(data["sector"]).strip(),
            sku=sku,
            quantity=quantity,
            low_stock_threshold=low_stock_threshold,
            purchase_price=purchase_price,
            sale_price=sale_price,
            expiry_date=expiry_date,
            updated_at=datetime.utcnow(),
        )
        db.session.add(product)
        db.session.flush()

        movement = StockMovement(
            company_id=company_scope(),
            product_id=product.id,
            movement_type="in",
            quantity=quantity,
            note="Initial stock",
        )
        db.session.add(movement)
        db.session.flush()

        create_accounting_entry(
            company_id=company_scope(),
            product_id=product.id,
            movement_id=movement.id,
            movement_type="in",
            amount=quantity * purchase_price,
        )

        db.session.commit()
        return jsonify(product_to_dict(product)), 201

    @app.route("/products/<int:product_id>", methods=["PUT"])
    @auth_required
    @roles_required("admin", "magasinier")
    def update_product(product_id: int):
        data = request.get_json(silent=True) or {}

        product = Product.query.filter_by(
            id=product_id,
            company_id=company_scope(),
        ).first()
        if product is None:
            return jsonify({"error": "Product not found."}), 404

        if "name" in data:
            product.name = str(data["name"]).strip()
        if "sector" in data:
            product.sector = str(data["sector"]).strip()
        if "sku" in data:
            sku = str(data["sku"]).strip()
            existing = Product.query.filter_by(company_id=company_scope(), sku=sku).first()
            if existing and existing.id != product.id:
                return jsonify({"error": "SKU already used in this company."}), 409
            product.sku = sku
        if "low_stock_threshold" in data:
            product.low_stock_threshold = int(data["low_stock_threshold"])
        if "purchase_price" in data:
            product.purchase_price = float(data["purchase_price"])
        if "sale_price" in data:
            product.sale_price = float(data["sale_price"])
        if "expiry_date" in data:
            product.expiry_date = datetime.fromisoformat(str(data["expiry_date"]))

        product.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify(product_to_dict(product))

    @app.route("/products/<int:product_id>", methods=["DELETE"])
    @auth_required
    @roles_required("admin")
    def delete_product(product_id: int):
        product = Product.query.filter_by(
            id=product_id,
            company_id=company_scope(),
        ).first()
        if product is None:
            return jsonify({"error": "Product not found."}), 404

        db.session.query(AccountingEntry).filter_by(
            product_id=product.id,
            company_id=company_scope(),
        ).delete()
        db.session.query(StockMovement).filter_by(
            product_id=product.id,
            company_id=company_scope(),
        ).delete()
        db.session.delete(product)
        db.session.commit()

        return jsonify({"status": "deleted"})

    @app.route("/movements", methods=["POST"])
    @auth_required
    @roles_required("admin", "magasinier")
    def create_movement():
        data = request.get_json(silent=True) or {}
        required = ["product_id", "movement_type", "quantity"]
        missing = [key for key in required if key not in data]
        if missing:
            return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

        movement_type = str(data["movement_type"]).strip().lower()
        if movement_type not in {"in", "out", "loss", "adjustment"}:
            return jsonify({"error": "Invalid movement_type."}), 400

        quantity = int(data["quantity"])
        if quantity <= 0:
            return jsonify({"error": "Quantity must be > 0."}), 400

        product = Product.query.filter_by(
            id=int(data["product_id"]),
            company_id=company_scope(),
        ).first()
        if product is None:
            return jsonify({"error": "Product not found."}), 404

        delta = quantity if movement_type == "in" else -quantity
        new_qty = product.quantity + delta
        if new_qty < 0:
            return jsonify({"error": "Insufficient stock."}), 409

        movement = StockMovement(
            company_id=company_scope(),
            product_id=product.id,
            movement_type=movement_type,
            quantity=quantity,
            note=data.get("note"),
        )
        db.session.add(movement)
        db.session.flush()

        product.quantity = new_qty
        product.updated_at = datetime.utcnow()

        create_accounting_entry(
            company_id=company_scope(),
            product_id=product.id,
            movement_id=movement.id,
            movement_type=movement_type,
            amount=quantity * product.purchase_price,
        )

        db.session.commit()
        return jsonify({"movement_id": movement.id, "product": product_to_dict(product)})

    @app.route("/movements", methods=["GET"])
    @auth_required
    def list_movements():
        rows = (
            StockMovement.query.filter_by(company_id=company_scope())
            .order_by(StockMovement.created_at.desc())
            .all()
        )
        return jsonify([movement_to_dict(r) for r in rows])

    @app.route("/accounting", methods=["GET"])
    @auth_required
    @roles_required("admin", "comptable")
    def list_accounting_entries():
        rows = (
            AccountingEntry.query.filter_by(company_id=company_scope())
            .order_by(AccountingEntry.created_at.desc())
            .all()
        )
        return jsonify([entry_to_dict(r) for r in rows])

    @app.route("/dashboard", methods=["GET"])
    @auth_required
    def dashboard():
        products = Product.query.filter_by(company_id=company_scope()).all()

        total_products = len(products)
        total_inventory_value = sum(p.purchase_price * p.quantity for p in products)
        potential_sales_value = sum(p.sale_price * p.quantity for p in products)
        expected_margin = potential_sales_value - total_inventory_value

        low_stock = [
            product_to_dict(p)
            for p in products
            if p.quantity < 50 or p.quantity < p.low_stock_threshold
        ]

        now = datetime.utcnow()
        next_month = now + timedelta(days=30)
        expiring_soon = [
            product_to_dict(p)
            for p in products
            if now <= p.expiry_date <= next_month
        ]

        by_sector = []
        sector_groups = {}
        for product in products:
            sector_groups.setdefault(product.sector, []).append(product)

        for sector, items in sorted(sector_groups.items(), key=lambda x: x[0]):
            by_sector.append(
                {
                    "sector": sector,
                    "product_count": len(items),
                    "total_quantity": sum(i.quantity for i in items),
                    "inventory_value": round(
                        sum(i.quantity * i.purchase_price for i in items),
                        2,
                    ),
                }
            )

        return jsonify(
            {
                "total_products": total_products,
                "total_inventory_value": round(total_inventory_value, 2),
                "potential_sales_value": round(potential_sales_value, 2),
                "expected_margin": round(expected_margin, 2),
                "low_stock_alerts": low_stock,
                "expiry_alerts": expiring_soon,
                "by_sector": by_sector,
            }
        )


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    CORS(app, resources={r"/*": {"origins": app.config["CORS_ORIGINS"]}})
    db.init_app(app)
    migrate.init_app(app, db)
    register_routes(app)

    with app.app_context():
        db.create_all()
        ensure_seed_data(app)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
