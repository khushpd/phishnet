import asyncio
from deepgram import DeepgramClient

DEEPGRAM_API_KEY = "YOUR_DEEPGRAM_API_KEY"

async def test():
    deepgram = DeepgramClient(api_key=DEEPGRAM_API_KEY)

    url = {"url": "https://static.deepgram.com/examples/Bueller-Life-moves-pretty-fast.wav"}

    options = {"model": "nova-2", "language": "en"}

    response = await deepgram.listen.asyncprerecorded.v("1").transcribe_url(url, options)

    transcript = response["results"]["channels"][0]["alternatives"][0]["transcript"]
    print("Transcript:", transcript)
    print("Deepgram is working correctly")

asyncio.run(test())