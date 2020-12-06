ARG PYTHON_VERSION=3.7.2-alpine

FROM python:${PYTHON_VERSION} as base
WORKDIR /app

RUN apk add --no-cache \
    build-base

COPY Pipfile Pipfile.lock ./

RUN pip install --no-cache-dir --upgrade pip==18.0 setuptools pipenv && \
    pipenv lock -r > requirements.txt && \
    pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

FROM python:${PYTHON_VERSION}
WORKDIR /app

COPY --from=base /wheels /wheels
COPY --from=base /app/requirements.txt /app/requirements.txt

RUN pip install --no-index --find-links=/wheels -r requirements.txt

COPY . .

EXPOSE 5000

ENTRYPOINT ["gunicorn", "--config", "gunicorn_config.py", "run:APP"]
