# Toleman platform developer workflow automation
.DEFAULT_GOAL := help

.PHONY: help start start-build stop clean restart logs

help: ## Show this help message
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""

start: ## Start all services in the background (Postgres, Redis, Backend, Celery, Frontend)
	docker compose up -d
	@echo "🚀 Stack started: Frontend http://localhost:3000 | Backend http://localhost:8000"

start-build: ## Rebuild images and start all services in the background
	docker compose up --build -d
	@echo "🛠️  Stack rebuilt: Frontend http://localhost:3000 | Backend http://localhost:8000"

stop: ## Stop all services (preserves database volume)
	docker compose down
	@echo "🛑 Stack stopped (database volume preserved)."

clean: ## Stop all services and remove data volumes
	docker compose down -v
	@echo "🧹 All containers and data volumes wiped."

restart: ## Restart all services
	docker compose restart
	@echo "🔄 Stack restarted."

logs: ## Follow container logs (e.g. make logs, or make logs s=backend)
	docker compose logs -f $(s)
