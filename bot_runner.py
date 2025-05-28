#!/usr/bin/env python3
"""
Standalone script to run the Telegram bot without asyncio issues.
This script uses a different approach from bot/bot.py to avoid event loop problems.
"""

import os
import sys
import logging
import asyncio
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Setup logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# Create a dedicated logger for this runner
logger = logging.getLogger("telegram_bot_runner")

# Make sure we can import from the bot package
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from bot.bot import (
    start, scan_command, exploit_command, crawl_command, 
    target_info_command, brute_command, vuln_command, exploit_vuln_command,
    handle_message, unknown, TELEGRAM_BOT_TOKEN
)

async def main():
    """Run the bot."""
    logger.info("Запуск Telegram бота...")
    
    # Initialize the application
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    # Add command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("scan", scan_command))
    application.add_handler(CommandHandler("exp", exploit_command))
    application.add_handler(CommandHandler("crawl", crawl_command))
    application.add_handler(CommandHandler("target_info", target_info_command))
    application.add_handler(CommandHandler("brute", brute_command))
    application.add_handler(CommandHandler("vuln", vuln_command))
    application.add_handler(CommandHandler("exploit_vuln", exploit_vuln_command))
    
    # Add message handler
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    # Add unknown command handler
    application.add_handler(MessageHandler(filters.COMMAND, unknown))
    
    # Start the bot
    await application.initialize()
    await application.start()
    await application.updater.start_polling()
    
    logger.info("Бот запущен и готов к работе")
    print("Бот запущен и работает. Нажмите Ctrl+C для остановки.")
    
    # Keep the bot running until interrupted
    try:
        await asyncio.Event().wait()  # Wait forever
    except (KeyboardInterrupt, SystemExit):
        logger.info("Получен сигнал остановки. Завершение работы бота...")
    finally:
        # Proper shutdown
        await application.updater.stop()
        await application.stop()
        await application.shutdown()
        logger.info("Бот остановлен")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logger.error(f"Ошибка при запуске бота: {e}")
        raise 