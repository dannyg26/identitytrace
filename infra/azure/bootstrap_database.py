"""Run once inside the VNet from an operator session, before starting the app.

The admin password is prompted without echo and is never stored in app settings.
Existing application roles are refused: this is a fresh-install tool, not an upgrade.
"""

import getpass
import os
import subprocess
import sys
import tempfile

import psycopg
from psycopg import sql

from infra.azure.startup import prepare_environment


def main():
    with tempfile.TemporaryDirectory(prefix="identitytrace-bootstrap-") as directory:
        environment = prepare_environment(os.environ, directory)
        password = getpass.getpass("PostgreSQL bootstrap administrator password: ")
        with psycopg.connect(host=os.environ["AZURE_PG_HOST"], dbname="identitytrace",
                             user="identitytrace_admin", password=password,
                             sslmode="verify-full", sslrootcert="/etc/ssl/certs/ca-certificates.crt") as connection:
            connection.execute(sql.SQL(
                "CREATE ROLE identitytrace LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS PASSWORD {}"
            ).format(sql.Literal(os.environ["AZURE_APP_DB_PASSWORD"])))
            connection.execute("REVOKE CONNECT ON DATABASE identitytrace FROM PUBLIC")
            connection.execute("GRANT CONNECT ON DATABASE identitytrace TO identitytrace")
            connection.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
            connection.execute("GRANT USAGE, CREATE ON SCHEMA public TO identitytrace")
        del password
        subprocess.run([sys.executable, "-m", "scripts.migrate_database", "--organization-id",
                        environment["IDENTITYTRACE_ORGANIZATION_ID"]], env=environment, check=True)
    print("Fresh database initialized and bound to the configured organization.")


if __name__ == "__main__":
    main()
