import os
import glob
import pandas as pd
from qdrant_client import QdrantClient, models
from sentence_transformers import SentenceTransformer

# ==============================================================
# ⚙️ CONFIGURATION
# ==============================================================
# 1. Path to the folder containing your CSV files
CSV_FOLDER_PATH = "my_csv_data"
# 2. The name of the column in your CSVs that contains the text to be embedded
TEXT_COLUMN_NAME = "Description"
# 3. How many rows to process at a time (to handle large files)
UPLOAD_BATCH_SIZE = 512
# 4. Qdrant connection URL
QDRANT_URL = "http://localhost:6333"
# 5. Name for your Qdrant collection
COLLECTION_NAME = "security_payloads_multi"
# 6. Name of the embedding model to use
MODEL_NAME = 'all-MiniLM-L6-v2'

# ==============================================================
# 🛠 FUNCTIONS
# ==============================================================

def ensure_collection_exists(client: QdrantClient, collection_name: str, embedding_dim: int):
    """Checks if a collection exists and creates it if it doesn't."""
    try:
        collection_info = client.get_collection(collection_name=collection_name)
        print(f"✅ Collection '{collection_name}' already exists.")
        return collection_info.points_count
    except Exception:
        print(f"⚠️ Collection '{collection_name}' not found. Creating it now...")
        client.create_collection(
            collection_name=collection_name,
            vectors_config=models.VectorParams(
                size=embedding_dim,
                distance=models.Distance.COSINE
            ),
        )
        print("✅ Collection created successfully.")
        return 0

def process_and_upload_csv(client: QdrantClient, model: SentenceTransformer, file_path: str, collection_name: str, starting_id: int):
    """Processes a single CSV file in chunks and uploads data to Qdrant."""
    print(f"\nProcessing file: {os.path.basename(file_path)}...")
    id_counter = starting_id
    total_rows = 0

    try:
        # Process the CSV in chunks to manage memory usage
        for chunk_df in pd.read_csv(file_path, chunksize=UPLOAD_BATCH_SIZE):
            # Ensure the text column exists
            if TEXT_COLUMN_NAME not in chunk_df.columns:
                print(f"🚨 Error: Column '{TEXT_COLUMN_NAME}' not found in {os.path.basename(file_path)}. Skipping chunk.")
                continue
            
            # Drop rows where the text column is empty
            chunk_df.dropna(subset=[TEXT_COLUMN_NAME], inplace=True)
            if chunk_df.empty:
                continue

            # Generate embeddings
            embeddings = model.encode(chunk_df[TEXT_COLUMN_NAME].tolist(), show_progress_bar=False)
            
            # Prepare metadata payloads
            payloads = chunk_df.to_dict(orient='records')
            
            # Upload points to Qdrant
            client.upsert(
                collection_name=collection_name,
                points=models.Batch(
                    ids=[i for i in range(id_counter, id_counter + len(chunk_df))],
                    vectors=embeddings,
                    payloads=payloads
                ),
                wait=True
            )
            id_counter += len(chunk_df)
            total_rows += len(chunk_df)
            print(f"  Uploaded {total_rows} rows so far...")

        print(f"✅ Successfully uploaded {total_rows} points from this file.")
        return id_counter

    except Exception as e:
        print(f"🚨 Failed to process {file_path}. Error: {e}")
        return starting_id # Return the original ID count if there was an error

# ==============================================================
# 🚀 MAIN SCRIPT
# ==============================================================

def main():
    """Main function to run the upload process."""
    print("🚀 Starting the data upload process to Qdrant...")
    
    # 1. Initialize clients
    model = SentenceTransformer(MODEL_NAME)
    client = QdrantClient(QDRANT_URL)
    
    # 2. Ensure collection exists and get the starting point ID
    embedding_dim = model.get_sentence_embedding_dimension()
    id_counter = ensure_collection_exists(client, COLLECTION_NAME, embedding_dim)
    
    # 3. Find CSV files
    csv_files = glob.glob(os.path.join(CSV_FOLDER_PATH, "*.csv"))
    if not csv_files:
        print(f"⚠️ No CSV files found in '{CSV_FOLDER_PATH}'. Exiting.")
        return
        
    print(f"📂 Found {len(csv_files)} CSV files to process.")
    
    # 4. Process each file
    for file_path in csv_files:
        id_counter = process_and_upload_csv(client, model, file_path, COLLECTION_NAME, id_counter)
        
    print(f"\n✨ Process complete. Total points in collection '{COLLECTION_NAME}': {id_counter}")

if __name__ == "__main__":
    main()