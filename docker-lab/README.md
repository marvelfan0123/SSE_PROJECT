# Scanning and Vulnerability Management Platform — Docker Lab

This folder provides a small, local-only lab for testing the **Scanning and Vulnerability Management Platform**.

## Safety
- Published web ports bind to `127.0.0.1`, so they are intended to be accessible only from this computer.
- These applications/images are deliberately vulnerable or outdated. Use only for this lab.
- Do not expose these ports to the internet or scan systems you do not own or have permission to test.
- The optional database has no host port mapping.

## Requirements
- Docker Desktop running
- Docker Compose v2 (`docker compose`)
- Nmap installed on Windows (optional for network discovery)

## Start the two web targets
From this folder, run:

```powershell
docker compose up -d juice-shop dvwa
docker ps
```

Open:
- Juice Shop: http://localhost:3000
- DVWA: http://localhost:8081

DVWA may take a short time to initialize. Follow the image's setup page if it asks for database initialization.

## Start optional legacy image targets
These older images are intended for Trivy image scans. They are optional and may have compatibility or download issues on newer systems.

```powershell
docker compose --profile legacy-targets up -d
```

This starts nginx on http://localhost:8082 plus the Python 3.7 and Node 12 containers.

## Start the optional database target
```powershell
docker compose --profile database up -d lab-db
```

The database is not published to a host port; it is only available inside Docker networking.

## Check running containers
```powershell
docker ps
```

## Use Nmap against the local web targets
Only scan this local lab:

```powershell
nmap -sV --top-ports 100 127.0.0.1
```

Because ports are published on localhost, Nmap can show the host ports (3000, 8081, and optionally 8082). This scan does not automatically enumerate every Docker container.

## Scan images with Trivy
If Trivy is installed, run:

```powershell
trivy image bkimminich/juice-shop
trivy image vulnerables/web-dvwa
trivy image nginx:1.14
trivy image python:3.7
trivy image node:12
```

## Stop the lab
Stop the web targets:

```powershell
docker compose down
```

Stop all optional profile services too:

```powershell
docker compose --profile legacy-targets --profile database down
```

This removes the containers created by Compose, but keeps downloaded images. No project dashboard files are included or changed by this lab package.
