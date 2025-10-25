# Validator X RAG

A multi-service backend application using FastAPI, PostgreSQL, Qdrant, and NGINX, orchestrated with Docker Compose.

## Services

- **Postgres**: Database for persistent storage.
- **Qdrant**: Vector database for semantic search.
- **rag-service**: Retrieval-Augmented Generation service (FastAPI).
- **validator-service**: Payload validation and incident logging (FastAPI).
- **NGINX**: Gateway and reverse proxy.

## Getting Started

1. **Clone the repository**
   ```bash
   git clone https://github.com/DheerajKumar018/validatorXrag.git
   cd validatorXrag
   ```

2. **Configure environment variables**
   - Edit `.env` as needed.

3. **Start all services**
   ```bash
   docker-compose up --build -d
   ```

4. **Access services**
   - Validator API: [http://localhost:8000](http://localhost:8000)
   - RAG API: [http://localhost:8001](http://localhost:8001)
   - NGINX Gateway: [http://localhost](http://localhost)

## Development

- Code for `validator-service` is in `/validator_service`
- Code for `rag-service` is in `/rag_service`
- NGINX config: `nginx.conf`
- Database data is persisted in Docker volumes

## Notes

- Exclude `venv/` and `my_csv_data/` from git (see `.gitignore`)
- For large files, use [Git LFS](https://git-lfs.github.com/)

---

**Author:** Dheeraj Kumar  
**Repo:** [validatorXrag](https://github.com/DheerajKumar018/validatorXrag)
