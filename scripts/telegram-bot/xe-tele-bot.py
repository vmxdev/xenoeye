import logging
import asyncio
import os

from aiogram import Bot, Dispatcher, executor, types

API_TOKEN = '...'

# list of chat id's
CHATS = []

POLL_INTERVAL = 10

MSGS_DIR = "/var/lib/xenoeye/telemsg/"

# Configure logging
logging.basicConfig(level=logging.INFO)

# Initialize bot and dispatcher
bot = Bot(token=API_TOKEN, parse_mode=types.ParseMode.HTML)
dp = Dispatcher(bot)


@dp.message_handler(commands=['start', 'help'])
async def send_welcome(message: types.Message):
    """
    This handler will be called when user sends `/start` or `/help` command
    """
    await message.reply("Hi!\nI'm xenoeye bot\nPowered by aiogram.")

@dp.message_handler(commands=['id'])
async def send_id(message: types.Message):
    await message.reply("Chat id: {}".format(message.chat.id))

@dp.message_handler()
async def any(message: types.Message):
    await message.answer("Only /id or /help commands allowed")


async def check_events():
    for filename in os.listdir(MSGS_DIR):
        full_name = os.path.join(MSGS_DIR, filename)
        if not os.path.isfile(full_name):
            continue
        filename_wo_ext = os.path.splitext(full_name)[0]

        if filename.endswith(".s"):
            # anomaly is gone
            if os.path.isfile(filename_wo_ext + ".n"):
                # and it was not reported
                # yellow
                msg_txt = "🟡 "
                f = open(filename_wo_ext + ".n", "r")
                msg_txt += f.read()
                f.close()

                msg_txt += "\n"
                f = open(filename_wo_ext + ".s", "r")
                msg_txt += f.read()
                f.close()

                for chat_id in CHATS:
                    await bot.send_message(chat_id, msg_txt)

                os.remove(full_name)
                os.remove(filename_wo_ext + ".n")
                # next file
                continue

            rfile_name = filename_wo_ext + ".-"

            # green
            msg_txt = "🟢 "
            f = open(full_name)
            msg_txt += f.read()
            f.close()

            if not os.path.isfile(rfile_name):
                # anomaly ended but no previous files left
                for chat_id in CHATS:
                    await bot.send_message(chat_id, msg_txt)
                os.remove(full_name)
                # next file
                continue

            f = open(rfile_name, "r")
            lines = f.readlines()
            for line in lines:
                # reply to start messages
                ls = line.split(":")
                chat_id = ls[0]
                msg_id = ls[1]
                await bot.send_message(chat_id, msg_txt, reply_to_message_id=msg_id)
            os.remove(full_name)
            os.remove(rfile_name)

        if filename.endswith(".n"):
            # new anomaly
            # red
            msg_txt = "🔴 "
            f = open(full_name, "r")
            msg_txt += f.read()
            f.close()
            out_name = filename_wo_ext + ".-tmp"
            f = open(out_name, "w")
            for chat_id in CHATS:
                msg = await bot.send_message(chat_id, msg_txt)
                f.write("{}:{}\n".format(chat_id, msg["message_id"]))
            f.close()
            os.rename(out_name, filename_wo_ext + ".-")
            os.remove(full_name)


def repeat(coro, loop):
    asyncio.ensure_future(coro(), loop=loop)
    loop.call_later(POLL_INTERVAL, repeat, coro, loop)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.call_later(POLL_INTERVAL, repeat, check_events, loop)
    executor.start_polling(dp, loop=loop, skip_updates=True)
