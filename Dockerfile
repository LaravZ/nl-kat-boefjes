FROM python:3.8

WORKDIR /app/boefjes

COPY nl-rt-tim-abang-boefjes/requirements-dev.txt .
RUN pip install -r requirements-dev.txt

COPY nl-rt-tim-abang-octopoes/ /app/octopoes
RUN pip install /app/octopoes

COPY nl-rt-tim-abang-boefjes/ .
RUN find . -name 'requirements.txt' -execdir pip install -r {} \;