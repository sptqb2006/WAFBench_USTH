# ==============================================================================
# WAFBench Automation Makefile
# ==============================================================================

SHELL := /bin/bash
COMPOSE := docker compose

.PHONY: help up down restart status reset mode-detection mode-blocking reload-waf logs test clean

help:
	@echo "======================================================================"
	@echo "WAFBench CLI - Infrastructure & Experimentation Control"
	@echo "======================================================================"
	@echo "  make up             - Launch all 7 services in docker-compose (background)"
	@echo "  make down           - Stop all services while preserving data volumes"
	@echo "  make restart        - Restart all running services"
	@echo "  make status         - Inspect container status and healthcheck results"
	@echo "  make reset          - Trigger fixture reset: POST 127.0.0.1:8001/health/reset"
	@echo "  make mode-detection - Switch WAF to DetectionOnly mode and reload Nginx"
	@echo "  make mode-blocking  - Switch WAF to Blocking (On) mode and reload Nginx"
	@echo "  make reload-waf     - Reload Nginx & ModSecurity inside wb-gateway"
	@echo "  make logs           - Stream live logs from all containers"
	@echo "  make test           - Execute automated 3-state test harness"
	@echo "  make clean          - Remove all containers, networks, and data volumes"
	@echo "======================================================================"

up:
	@echo "[+] Starting WAFBench laboratory (7 microservices)..."
	$(COMPOSE) up -d --build

down:
	@echo "[-] Stopping WAFBench laboratory..."
	$(COMPOSE) down

restart:
	@echo "[*] Restarting services..."
	$(COMPOSE) restart

status:
	@echo "[*] Service status and health checks:"
	$(COMPOSE) ps

reset:
	@echo "[*] Triggering application fixture reset (POST 127.0.0.1:8001/health/reset)..."
	@curl -s -X POST http://127.0.0.1:8001/health/reset | jq . || curl -s -X POST http://127.0.0.1:8001/health/reset

mode-detection:
	@echo "[*] Activating WAF mode: DetectionOnly"
	@sed -i 's/^WAF_RULE_ENGINE=.*/WAF_RULE_ENGINE=DetectionOnly/' .env 2>/dev/null || true
	@docker exec wb-gateway sed -i 's/SecRuleEngine .*/SecRuleEngine DetectionOnly/' /etc/modsecurity.d/main.conf 2>/dev/null || true
	@$(MAKE) reload-waf
	@echo "[OK] DetectionOnly mode successfully activated."

mode-blocking:
	@echo "[*] Activating WAF mode: Blocking (On)"
	@sed -i 's/^WAF_RULE_ENGINE=.*/WAF_RULE_ENGINE=On/' .env 2>/dev/null || true
	@docker exec wb-gateway sed -i 's/SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity.d/main.conf 2>/dev/null || true
	@$(MAKE) reload-waf
	@echo "[OK] Blocking mode successfully activated."

reload-waf:
	@echo "[*] Reloading Nginx & ModSecurity configuration..."
	@docker exec wb-gateway nginx -s reload 2>/dev/null || true

logs:
	$(COMPOSE) logs -f

test:
	@echo "[*] Executing test runner..."
	@python3 runner/test.py

clean:
	@echo "[!] Purging all containers, volumes, and networks..."
	$(COMPOSE) down -v --remove-orphans
