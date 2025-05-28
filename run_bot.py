#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Веб-сканнер уязвимостей с Telegram ботом
Скрипт для запуска Telegram бота отдельно от основного приложения.

Автор: AI-разработчик
Версия: 1.0.0
"""

import os
import sys
import logging
import asyncio
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# добавляем текущую директорию в path для импорта модулей
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# импортируем обработчики команд из модуля bot
from bot.bot import (
    start, scan_command, exploit_command, crawl_command, 
    handle_message, unknown, TELEGRAM_BOT_TOKEN
)

# настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("bot_run.log")
    ]
)
logger = logging.getLogger("telegram_bot_runner")

async def main():
    """Основная функция запуска бота"""
    try:
        # проверяем токен
        if not TELEGRAM_BOT_TOKEN or TELEGRAM_BOT_TOKEN == 'YOUR_TELEGRAM_BOT_TOKEN':
            logger.error("Не задан токен Telegram бота")
            print("Ошибка: Токен Telegram бота не задан в bot/bot.py")
            return
        
        # создаем приложение
        application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
        
        # регистрируем обработчики
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("scan", scan_command))
        application.add_handler(CommandHandler("exp", exploit_command))
        application.add_handler(CommandHandler("crawl", crawl_command))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
        application.add_handler(MessageHandler(filters.COMMAND, unknown))
        
        # запускаем бота
        logger.info("Запуск Telegram бота...")
        await application.initialize()
        await application.start()
        await application.updater.start_polling(allowed_updates=Update.ALL_TYPES)
        
        logger.info("Бот запущен и готов к работе")
        print("Бот запущен и работает. Нажмите Ctrl+C для остановки.")
        
        # ждем сигнала остановки
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Получен сигнал остановки бота")
        print("\nОстановка бота...")
        
        # корректно останавливаем бота
        if 'application' in locals():
            await application.updater.stop()
            await application.stop()
            await application.shutdown()
        
    except Exception as e:
        logger.error(f"Ошибка при запуске бота: {e}")
        import traceback
        logger.error(f"Трассировка ошибки:\n{traceback.format_exc()}")
        print(f"Произошла ошибка: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nБот остановлен.")
    except Exception as e:
        print(f"Критическая ошибка: {e}")
        logging.error(f"Критическая ошибка: {e}", exc_info=True) 