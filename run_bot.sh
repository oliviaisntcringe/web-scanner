#!/bin/bash

# Ensure we're in the right directory
cd "$(dirname "$0")"

# Kill any existing python processes
pkill -f "python3 -m bot.bot" || true

# Wait a moment
sleep 1

# Start the bot
python3 -m bot.bot 