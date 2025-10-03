# api.py
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os, shutil, uuid

from ner import redact_file

class AppConfig(BaseModel):
    upload_dir: str = "uploads"
    output_dir: str = "out"

config = AppConfig()
os.makedirs(config.upload_dir, exist_ok=True)
os.makedirs(config.output_dir, exist_ok=True)

app = FastAPI()

@app.post("/redact")
async def redact(file: UploadFile = File(...)):
    uid = str(uuid.uuid4())
    in_path = os.path.join(config.upload_dir, f"{uid}_{file.filename}")
    out_path = os.path.join(config.output_dir, f"redacted_{file.filename}")

 
    with open(in_path, "wb") as f:
        shutil.copyfileobj(file.file, f)


    redact_file(in_path, out_path)

    return FileResponse(out_path, filename=f"redacted_{file.filename}")
