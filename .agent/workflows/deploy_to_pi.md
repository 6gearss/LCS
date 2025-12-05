---
description: Deploy code to Raspberry Pi using rsync
---

This workflow syncs your current project folder to the Raspberry Pi.

# Prerequisites
- You must have SSH access to your Raspberry Pi.
- `rsync` must be installed on both your Mac and the Pi.

# Configuration
Set your Pi's details below.
- PI_USER: `pi` (or your username)
- PI_HOST: `raspberrypi.local` (or IP address)
- DEST_DIR: `~/LCS`

# Command
Run the following command in your terminal. 

```bash
# syntax: rsync -avz --exclude '.git' --exclude '__pycache__' --exclude '.venv' [RELEASE_DIR]/ [USER]@[HOST]:[DEST_DIR]

rsync -avz --exclude '.git' --exclude '__pycache__' --exclude '.venv' ./ pi@raspberrypi.local:~/LCS
```

# Automation
You can save this as a script `deploy.sh`:

```bash
#!/bin/bash
PI_USER="pi"
PI_HOST="raspberrypi.local"
DEST_DIR="~/LCS"

echo "Deploying to $PI_USER@$PI_HOST:$DEST_DIR..."
rsync -avz --exclude '.git' --exclude '__pycache__' --exclude '.venv' ./ $PI_USER@$PI_HOST:$DEST_DIR
echo "Done!"
```

Change `chmod +x deploy.sh` to make it executable.
