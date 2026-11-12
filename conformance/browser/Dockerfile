# The Playwright image carries Chromium built for this exact Playwright version, so the two pins move together
FROM mcr.microsoft.com/playwright/python:v1.64.1-noble

WORKDIR /driver
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages --only-binary :all: --require-hashes -r requirements.txt

COPY driver.py .

USER pwuser
ENTRYPOINT ["python3", "/driver/driver.py"]
