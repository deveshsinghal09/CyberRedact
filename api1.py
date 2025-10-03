# api.py
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os, shutil, uuid

from pyredactkit.core_redactor import CoreRedactorEngine


class AppConfig(BaseModel):
    upload_dir: str = "uploads"
    output_dir: str = "out"

config = AppConfig()

os.makedirs(config.upload_dir, exist_ok=True)
os.makedirs(config.output_dir, exist_ok=True)


app = FastAPI()
core = CoreRedactorEngine()

class ErrorResponse(BaseModel):
    error: str

@app.post("/redact", responses={500: {"model": ErrorResponse}})
async def redact(file: UploadFile = File(...)):
    uid = str(uuid.uuid4())
    in_path = os.path.join(config.upload_dir, f"{uid}_{file.filename}")
    
    with open(in_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    core.process_core_file(in_path, config.output_dir + "/")
    redacted_path = os.path.join(config.output_dir, f"redacted_{os.path.basename(in_path)}")

    if not os.path.exists(redacted_path):
        return {"error": "Redaction failed"}  

    return FileResponse(redacted_path, filename=f"redacted_{file.filename}")
