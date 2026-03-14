# Getting Started

Welcome to the Network Scanner and Discovery Tool. This guide will walk you through the essential steps to configure and run your first subnet or target sweep.

## Prerequisites

Ensure all dependencies are installed via the provided requirements file:

``` bash
pip install -r requirements.txt
```

*(Note: You will also need an underlying OS-level installation of Nmap for subnet sweeping to work).*

## Critical Setup Steps

Before running the orchestrator, you must prepare your environment by defining your targets and credentials.

### 1\. Copy the sample config folder for this run

We recommend organizing your scans by creating a dedicated directory for each client or project (for example, `XYZcorp_scanning`) and seeding it from the provided sample config folder.

On Bash:

``` bash
cp -r docs/sample_config_files XYZcorp_scanning
```

On PowerShell:

``` powershell
Copy-Item -Recurse docs/sample_config_files XYZcorp_scanning
```

This gives you a minimum starting set of files to edit for that run:

``` text
XYZcorp_scanning/
  targets.csv
  keys.yaml
  ssh_commands.yaml
  db-local-sqlite.yaml
  db-mysql.yaml
  db-postgresql.yaml
```

If you want to use the command examples later in this guide exactly as written, rename or copy the database sample you want to use to `XYZcorp_scanning/db.yaml`. For example, for a local SQLite-backed run (and then delete the db.yaml samples you aren't using).

### 2\. Edit `targets.csv`

Edit the copied `targets.csv` file to outline the targets you want to scan.

This file can contain single IP addresses or CIDR notations. You can provide an arbitrary number of top-level keytags in the columns following the IP. If you list tags, the scanner will only attempt the credentials associated with those specific keytags to save time ("constrained scan"). If you leave them blank, it will try every keytag defined in your yaml file ("unconstrained scan").

``` csv
ip_or_subnet,keytag1,keytag2,keytag3
10.0.0.1,site_a_admin,global_read_only,
192.168.100.0/24,site_a_admin,,
10.1.1.5,,,
```

### 3\. Edit `keys.yaml`

Edit the copied `keys.yaml` file to contain the raw passwords, keys, and community strings your organization uses.

The primary tags defined at the top level of this file (e.g., `site_a_admin`) map to the names you used in the CSV. Inside these top-level tags, you group the appropriate auth types (snmpv2, snmpv3, ssh\_password, ssh\_key) and define an array of possible credentials for each type.

The scanner stores only credential references in the database, not secrets. Successful SNMP attempts are recorded as `<keytag>:<index>`, while successful SSH attempts are recorded as `<keytag>:p<index>` for password entries or `<keytag>:k<index>` for key entries.

``` yaml
site_a_admin:
  snmpv2:
    - "public"
    - "private"
  ssh_password:
    - username: "admin"
      password: "SuperSecretPassword"

global_read_only:
  snmpv3:
    - username: "readonly"
      auth_protocol: "SHA"
      auth_key: "authpass123"
      priv_protocol: "AES"
      priv_key: "privpass123"
  ssh_key:
    - username: "automation"
      key_file: "/path/to/id_rsa"
```

### 4\. Choose and edit `db.yaml`

Choose one of the copied database sample files, rename or copy it to `db.yaml`, and then edit it for your environment. It must contain exactly one top-level key named `db`.

SQLite example:

``` yaml
db:
  type: sqlite
  dbfile: scan_results/discovery_results.sqlite
```

PostgreSQL example:

``` yaml
db:
  type: postgresql
  host: db.example.com
  port: 5432
  database: discovery_inventory
  username: scanner_user
  password_env: DISCOVERY_DB_PASSWORD
  ssl_mode: require
  connect_timeout: 10
```

MySQL or MariaDB example:

``` yaml
db:
  type: mariadb
  host: db.example.com
  port: 3306
  database: discovery_inventory
  username: scanner_user
  password: change_me
  charset: utf8mb4
  connect_timeout: 10
```

If the target database already exists but has no scanner tables, the scanner will initialize the schema automatically. For remote backends, the database itself must already exist and the account must have permission to create tables.

### 5\. Validate `ssh_commands.yaml`

Review the copied `XYZcorp_scanning/ssh_commands.yaml` file. This critical file maps SNMP identification strings to specific Netmiko OS profiles, and defines the exact `show` commands the script will execute once SSH access is obtained. Customize this file to add or remove commands you want archived.

## How to Run the Scanner

At this point, your client or project folder should contain the run-specific `targets.csv`, `keys.yaml`, `ssh_commands.yaml`, and `db.yaml` files.

From the root directory of the tool, run the orchestrator and point the arguments to your client folder:

``` bash
python src/scanner_orchestrator.py \
    --targets XYZcorp_scanning/targets.csv \
    --keys XYZcorp_scanning/keys.yaml \
    --ssh-commands XYZcorp_scanning/ssh_commands.yaml \
    --dbconfig XYZcorp_scanning/db.yaml \
    --evidence-dir XYZcorp_scanning/scan_results \
    --max-workers-per-db-connection 20 \
    --max-db-connections 1
```

SQLite requires `--max-db-connections 1`, but it can still run many concurrent scan workers behind that single writer connection.  (default 10 workers but many more are possible)

For external PostgreSQL, MySQL, or MariaDB databases, you can raise both values. For example, this allows up to 500 active scans:

``` bash
python src/scanner_orchestrator.py \
    --targets XYZcorp_scanning/targets.csv \
    --keys XYZcorp_scanning/keys.yaml \
    --ssh-commands XYZcorp_scanning/ssh_commands.yaml \
    --dbconfig XYZcorp_scanning/db.yaml \
    --evidence-dir XYZcorp_scanning/scan_results \
    --max-workers-per-db-connection 20 \
    --max-db-connections 25
```

This will:

1. Connect to the database defined in `db.yaml` and initialize the schema if the database is blank.
2. Generate a new timestamped folder inside `scan_results/` holding all the raw CLI output traces for devices polled on this specific run.
3. Resolve overlapping target rules so the most specific IP or subnet entry wins.
4. Recursively map alive hosts, polling SNMP and executing SSH through bounded worker threads.
5. Persist completed IP results through dedicated DB writer threads.

*(For detailed testing parameters and individual module executions, check `docs/testing_instructions/testing_guide.md`).*

## Browsing the Results

Once your scan is complete, you can review the configured database natively or utilize our browser tools located in the `src/browser/` directory.

### Tabular Browser

To view a text-based, tabular representation of your scan iterations and evidence, available at [http://localhost:5501](http://localhost:5501):

``` bash
python src/browser/tabular_browser.py --dbconfig XYZcorp_scanning/db.yaml --directory XYZcorp_scanning/scan_results --port 5501
```

### Graphical Browser

To launch a rich, graphical view rendering the relationships and stored configurations dynamically, available at [http://localhost:5502](http://localhost:5502):

``` bash
python src/browser/graphical_browser.py --dbconfig XYZcorp_scanning/db.yaml --directory XYZcorp_scanning/scan_results --port 5502
```

- - -

## Attribution and License

Copyright 2026 Benjamin Brillat

Author: Benjamin Brillat
GitHub: [brillb](https://github.com/brillb)

This document is part of the `brillb/network-discovery-scanner` project.

Co-authored using AI coding assist modules in the IDE, including GPT,
Copilot, Gemini, and similar tools.

Licensed under the Apache License, Version 2.0. You may obtain a copy of the
license in the repository `LICENSE` file or at:
[https://www.apache.org/licenses/LICENSE-2.0](https://www.apache.org/licenses/LICENSE-2.0)

SPDX-License-Identifier: Apache-2.0