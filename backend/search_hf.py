from huggingface_hub import HfApi
api = HfApi()
models = api.list_models(search="deepfake audio", limit=10)
for m in models:
    print(m.modelId)
