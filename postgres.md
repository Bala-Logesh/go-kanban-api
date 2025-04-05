# Instructions to setup Postgres on Docker

```
docker pull postgres
```

```
docker run -d --name postgres -e POSTGRES_PASSWORD=password -e POSTGRES_DB=kanbanapi -p 5432:5432 postgres

```

```
docker ps
```

```
docker exec -it postgres createdb -U postgres kanbanapi
```

```
docker exec -it postgres psql -U postgres
```
Inside the psql prompt

```
\c kanbanapi
```

```
\q
```
