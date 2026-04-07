PORT ?= 5001

.PHONY: start stop restart logs install docker docker-stop help

help:
	@echo "MSRA — Mobile Security Review Assistant"
	@echo ""
	@echo "  make start        Start the dashboard (opens browser)"
	@echo "  make stop         Stop the dashboard"
	@echo "  make restart      Restart the dashboard"
	@echo "  make logs         Tail server logs"
	@echo "  make install      Install Python dependencies"
	@echo "  make docker       Start with Docker Compose"
	@echo "  make docker-stop  Stop Docker containers"

start:
	@bash start.sh

stop:
	@bash stop.sh

restart: stop start

logs:
	@tail -f /tmp/msra_server.log

install:
	pip3 install flask weasyprint anthropic
	@echo ""
	@echo "External tools required:"
	@echo "  jadx: brew install jadx  (APK decompilation)"
	@echo "  adb:  brew install android-platform-tools  (dynamic analysis)"

docker:
	docker compose up -d
	@echo "MSRA → http://localhost:$(PORT)"

docker-stop:
	docker compose down
