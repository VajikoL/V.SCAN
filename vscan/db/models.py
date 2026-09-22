"""SQLAlchemy models for scan history (Vazha Lomtatidze / V.SCAN)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from vscan.config import HISTORY_DB, ensure_dirs


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    target: Mapped[str] = mapped_column(String(255))
    profile: Mapped[str] = mapped_column(String(64), default="balanced")
    device_count: Mapped[int] = mapped_column(Integer, default=0)
    vuln_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    notes: Mapped[str] = mapped_column(Text, default="")

    devices: Mapped[list[DeviceRecord]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    vulns: Mapped[list[VulnRecord]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class DeviceRecord(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    ip: Mapped[str] = mapped_column(String(64))
    mac: Mapped[str] = mapped_column(String(64), default="")
    vendor: Mapped[str] = mapped_column(String(255), default="")
    hostname: Mapped[str] = mapped_column(String(255), default="")
    device_type: Mapped[str] = mapped_column(String(64), default="")
    os_guess: Mapped[str] = mapped_column(String(255), default="")
    open_ports: Mapped[str] = mapped_column(Text, default="")
    services_json: Mapped[str] = mapped_column(Text, default="[]")

    scan: Mapped[ScanRecord] = relationship(back_populates="devices")


class VulnRecord(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    ip: Mapped[str] = mapped_column(String(64))
    port: Mapped[int] = mapped_column(Integer, default=0)
    service: Mapped[str] = mapped_column(String(128), default="")
    product: Mapped[str] = mapped_column(String(255), default="")
    version: Mapped[str] = mapped_column(String(128), default="")
    cve_id: Mapped[str] = mapped_column(String(64))
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), default="none")
    title: Mapped[str] = mapped_column(String(512), default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    nvd_url: Mapped[str] = mapped_column(String(512), default="")
    category: Mapped[str] = mapped_column(String(64), default="")

    scan: Mapped[ScanRecord] = relationship(back_populates="vulns")


_engine = None
_Session = None


def _migrate(engine) -> None:
    """Additive SQLite migrations for existing ~/.vscan/history.db installs."""
    with engine.begin() as conn:
        scan_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(scans)"))}
        if "risk_score" not in scan_cols:
            conn.execute(text("ALTER TABLE scans ADD COLUMN risk_score REAL DEFAULT 0"))
        vuln_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(vulnerabilities)"))}
        if "category" not in vuln_cols:
            conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN category VARCHAR(64) DEFAULT ''"))


def get_session_factory():
    global _engine, _Session
    ensure_dirs()
    if _engine is None:
        _engine = create_engine(f"sqlite:///{HISTORY_DB}", future=True)
        Base.metadata.create_all(_engine)
        _migrate(_engine)
        _Session = sessionmaker(bind=_engine, expire_on_commit=False)
    return _Session
