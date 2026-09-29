FROM ubuntu:latest

WORKDIR /app

RUN useradd -m ctf

COPY l* main main.c flag.txt ./

RUN chmod +x main

USER ctf

EXPOSE 5000

CMD ["./main"]
