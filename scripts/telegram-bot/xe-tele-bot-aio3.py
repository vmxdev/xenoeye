import logging
import asyncio
import os

from aiogram import Bot, Dispatcher, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.types import Message
from aiogram.filters import Command, CommandObject, CommandStart

API_TOKEN = '...'

# list of chat id's
CHATS = []

POLL_INTERVAL = 10

MSGS_DIR = "/var/lib/xenoeye/telemsg/"

# Configure logging
logging.basicConfig(level=logging.INFO)

# Initialize bot and dispatcher
bot = Bot(token=API_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher()


@dp.channel_post(Command("help"))
@dp.channel_post(CommandStart())
@dp.message(Command("help"))
@dp.message(CommandStart())
async def send_welcome(message: Message):
    """
    This handler will be called when user sends `/start` or `/help` command
    """
    await message.reply("Hi!\nI'm xenoeye bot\nPowered by aiogram.")

@dp.channel_post(Command("id"))
@dp.message(Command("id"))
async def send_id(message: types.Message):
    await message.reply("Chat id: {}".format(message.chat.id))

async def check_events():
    for filename in os.listdir(MSGS_DIR):
        full_name = os.path.join(MSGS_DIR, filename)
        if not os.path.isfile(full_name):
            continue
        filename_wo_ext = os.path.splitext(full_name)[0]

        if filename.endswith(".s"):
            # anomaly is gone
            # green
            msg_txt = "🟢 "
            f = open(full_name)
            msg_txt += f.read()
            f.close()
            pfile_name = filename_wo_ext + ".p"

            if os.path.isfile(pfile_name):
                f = open(pfile_name, "r")
                lines = f.readlines()
                for line in lines:
                    # reply to start messages
                    ls = line.split(":")
                    chat_id = ls[0]
                    msg_id = ls[1]
                    await bot.send_message(chat_id, msg_txt, reply_to_message_id=msg_id)
                os.remove(full_name)
                os.remove(pfile_name)
                continue
            else:
                if not os.path.isfile(filename_wo_ext + ".n"):
                    # anomaly ended but no previous files left
                    for chat_id in CHATS:
                        await bot.send_message(chat_id, msg_txt)
                    os.remove(full_name)
                    continue

            if os.path.isfile(filename_wo_ext + ".n"):
                # anomaly is gone but was not reported
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

    # second pass
    for filename in os.listdir(MSGS_DIR):
        full_name = os.path.join(MSGS_DIR, filename)
        if not os.path.isfile(full_name):
            continue
        filename_wo_ext = os.path.splitext(full_name)[0]
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
                f.write("{}:{}\n".format(chat_id, msg.message_id))
            f.close()
            os.rename(out_name, filename_wo_ext + ".p")
            os.remove(full_name)


def repeat(coro, loop):
    asyncio.ensure_future(coro(), loop=loop)
    loop.call_later(POLL_INTERVAL, repeat, coro, loop)

async def main():
    loop = asyncio.get_event_loop()
    loop.call_later(POLL_INTERVAL, repeat, check_events, loop)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
