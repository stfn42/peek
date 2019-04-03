FROM python:3

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY peek/peek.py ./peek.py

ENTRYPOINT ["python", "./peek.py"]
