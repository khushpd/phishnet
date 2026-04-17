import asyncio
from deepgram import DeepgramClient

DEEPGRAM_API_KEY = "42cfcc31320026fa12e1a1841994c4d9be281c03"

async def test():
    deepgram = DeepgramClient(api_key=DEEPGRAM_API_KEY)

    url = {"url": "https://static.deepgram.com/examples/Bueller-Life-moves-pretty-fast.wav"}

    options = {"model": "nova-2", "language": "en"}

    response = await deepgram.listen.asyncprerecorded.v("1").transcribe_url(url, options)

    transcript = response["results"]["channels"][0]["alternatives"][0]["transcript"]
    print("Transcript:", transcript)
    print("Deepgram is working correctly")

asyncio.run(test())