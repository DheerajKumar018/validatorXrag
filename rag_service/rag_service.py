import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from qdrant_client import QdrantClient, models
from sentence_transformers import SentenceTransformer # Import the embedding model

# ==============================================================
# ⚙️ CONFIGURATION
# ==============================================================
QDRANT_URL = os.getenv("QDRANT_URL")
if not QDRANT_URL:
    raise RuntimeError("❌ QDRANT_URL environment variable not set!")

COLLECTION_NAME = "security_payloads_multi"
MODEL_NAME = 'all-MiniLM-L6-v2'
VECTOR_SIZE = 384 # This must match the model's output dimension
# A threshold for similarity. If a search result's score is above this,
# we consider it a potential match. Adjust this based on testing.
SIMILARITY_THRESHOLD = 0.85

# ==============================================================
# 🚀 INITIALIZATION
# ==============================================================
app = FastAPI(title="Vector Search Analysis Service", version="1.0")
client = QdrantClient(url=QDRANT_URL)
# Create a payload index on the 'color' field
client.create_payload_index(
    collection_name="security_payloads_multi",
    field_name="color",
    field_schema="keyword" # Use 'keyword' for text, 'integer' for numbers, etc.
)
# Load the sentence transformer model on startup
model = SentenceTransformer(MODEL_NAME)

class Payload(BaseModel):
    payload: str

# ==============================================================
# 🧠 CORE LOGIC
# ==============================================================

def get_embedding(text: str):
    """Encodes text into a vector using the SentenceTransformer model."""
    print(f"Embedding text: {text[:30]}...")
    # The model.encode() function returns a NumPy array, which we convert to a list
    return model.encode(text).tolist()

def make_verdict_from_qdrant(search_results: list) -> dict:
    """Makes a verdict based on the similarity score of Qdrant results."""
    if not search_results:
        return {"verdict": "benign", "reason": "No similar patterns found in knowledge base."}

    # Get the best matching result
    best_match = search_results[0]
    score = best_match.score
    
    print(f"Highest similarity score from Qdrant: {score:.4f}")

    # If the similarity score is above our defined threshold, flag it as malicious
    if score > SIMILARITY_THRESHOLD:
        detected_pattern = best_match.payload.get("Description", "Unknown Pattern")
        return {
            "verdict": "malicious",
            "detected_pattern": detected_pattern,
            "reason": f"Payload is {score*100:.2f}% similar to a known malicious pattern."
        }
    
    return {"verdict": "benign", "reason": "Similarity score below threshold."}

# ==============================================================
# 🔗 API ENDPOINT
# ==============================================================

@app.post("/analyze-payload")
def analyze_payload(data: Payload):
    """Receives a payload and makes a verdict based on a Qdrant vector search."""
    print(f"RAG service received payload: {data.payload}")
    try:
        # 1. Embed the incoming payload
        payload_vector = get_embedding(data.payload)

        # 2. Search Qdrant for similar known patterns
        search_results = client.search(
            collection_name=COLLECTION_NAME,
            query_vector=payload_vector,
            limit=1 # We only need the top result for this logic
        )
        
        # 3. Make a final decision based on the search results
        verdict = make_verdict_from_qdrant(search_results)
        
        return verdict

    except Exception as e:
        print(f"❌ An error occurred during analysis: {e}")
        raise HTTPException(status_code=500, detail="Error during analysis")

# ==============================================================
# ⚡ SERVER STARTUP LOGIC
# ==============================================================

@app.on_event("startup")
def startup_event():
    """Ensures the Qdrant collection exists when the server starts."""
    try:
        client.get_collection(collection_name=COLLECTION_NAME)
        print(f"✅ Qdrant collection '{COLLECTION_NAME}' already exists.")
    except Exception:
        print(f"⚠️ Qdrant collection '{COLLECTION_NAME}' not found. Creating it now.")
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=models.VectorParams(size=VECTOR_SIZE, distance=models.Distance.COSINE),
        )
        print(f"✅ Collection '{COLLECTION_NAME}' created successfully.")