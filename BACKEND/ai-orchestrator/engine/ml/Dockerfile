FROM python:3.12-slim

WORKDIR /workspace

COPY BACKEND/api/requirements-unified.txt /workspace/requirements.txt
RUN pip install --no-cache-dir -r /workspace/requirements.txt

COPY . /workspace

CMD ["python", "BACKEND/ai-orchestrator/engine/ml/trainer_entrypoint.py"]
