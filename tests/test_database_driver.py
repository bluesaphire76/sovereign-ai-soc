from pathlib import Path
import runpy


def test_database_uses_installed_psycopg2_driver(monkeypatch):
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    for name, value in {
        "POSTGRES_HOST": "127.0.0.1",
        "POSTGRES_PORT": "5432",
        "POSTGRES_DB": "ai_soc_ci",
        "POSTGRES_USER": "ai_soc_ci",
        "POSTGRES_PASSWORD": "ci-only",
    }.items():
        monkeypatch.setenv(name, value)

    # Loading the engine must work without psycopg 3 or a live database.
    database = runpy.run_path(str(Path(__file__).resolve().parents[1] / "database.py"))
    engine = database["engine"]
    try:
        assert engine.dialect.driver == "psycopg2"
        assert engine.dialect.dbapi.__name__ == "psycopg2"
        with database["SessionLocal"]() as session:
            assert session.get_bind() is engine
    finally:
        engine.dispose()
