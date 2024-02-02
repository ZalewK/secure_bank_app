FROM python:3-alpine

ENV TZ=Europe/Warsaw

WORKDIR /app
 
COPY requirements.txt ./
 
RUN pip install -r requirements.txt
 
COPY . .

CMD [ "python", "wsgi.py" ]