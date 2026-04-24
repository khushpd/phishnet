import asyncio
import websockets
import json

async def test_ws():
    uri = "ws://127.0.0.1:8000/api/analyze/audio"
    try:
        async with websockets.connect(uri) as ws:
            # Send exactly 160,001 bytes of dummy audio
            dummy_audio = b'\x00' * 160001
            await ws.send(dummy_audio)
            response = await ws.recv()
            print("Received:", response)
    except Exception as e:
        print("WS Error:", e)

asyncio.run(test_ws())
