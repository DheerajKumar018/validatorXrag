# Use the same base image for consistency
FROM arm64v8/python:3.11-slim

# Set the working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Expose the internal port
EXPOSE 8000

# The command to run the RAG service
CMD ["uvicorn", "rag_service:app", "--host", "0.0.0.0", "--port", "8000"]