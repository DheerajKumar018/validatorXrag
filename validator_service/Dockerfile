# Use an official, slim Python runtime as a parent image
FROM arm64v8/python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file first to leverage Docker's layer caching
COPY requirements.txt .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code into the container
COPY . .

# Expose the port the app runs on
EXPOSE 8000

# The command to run your application when the container starts
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]