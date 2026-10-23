PORT ?= 5001

.PHONY: test start stop restart logs install update docker docker-stop help

help:
	@echo "MSRA — Mobile Security Review Assistant"
	@echo ""
	@echo "  make start        Start the dashboard (opens browser)"
	@echo "  make stop         Stop the dashboard"
	@echo "  make restart      Restart the dashboard"
	@echo "  make update       Pull latest version and restart"
	@echo "  make test         Run the test suite"
	@echo "  make logs         Tail server logs"
	@echo "  make install      Install Python dependencies"
	@echo "  make docker       Start with Docker Compose"
	@echo "  make docker-stop  Stop Docker containers"

start:
	@bash start.sh

stop:
	@bash stop.sh

restart: stop start

update:
	@bash update.sh

logs:
	@tail -f /tmp/msra_server.log

test:
	python3 -m pytest -q

install:
	pip3 install -r requirements.txt
	@echo ""
	@echo "External tools required:"
	@echo "  jadx: brew install jadx  (APK decompilation)"
	@echo "  adb:  brew install android-platform-tools  (dynamic analysis)"
	@echo "  PDF:  brew install pango cairo gdk-pixbuf  (macOS, for PDF export)"

docker:
	docker compose up -d
	@echo "MSRA → http://localhost:$(PORT)"

docker-stop:
	docker compose down
