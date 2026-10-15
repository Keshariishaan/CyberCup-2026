# PURPOSE: developer shortcuts. HOW TO EXTEND: add targets.
.PHONY: install api ui test eval migrate up
install:
	pip install -r requirements.txt
api:
	uvicorn shieldgate.main:app --reload --port 8000
ui:
	API_URL=http://localhost:8000 streamlit run frontend/app.py
test:
	pytest -q
eval:
	python tests/evaluate.py
migrate:
	alembic upgrade head
up:
	docker compose up --build
