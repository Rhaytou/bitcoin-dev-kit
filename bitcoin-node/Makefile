.PHONY: up down docker_clean_all


# General worflow
## Start all Docker containers
up:
	docker compose up -d --build

## Stop and remove all Docker containers and volumes defined in docker compose
down:
	docker compose down -v

## Full Docker cleanup
docker_clean_all:
	docker stop $$(docker ps -aq) 2>/dev/null || true && \
	docker rm -f $$(docker ps -aq) 2>/dev/null || true && \
	docker rmi -f $$(docker images -q) 2>/dev/null || true && \
	docker volume rm $$(docker volume ls -q) 2>/dev/null || true && \
	docker network rm $$(docker network ls -q | grep -v "bridge\|host\|none") 2>/dev/null || true && \
	docker system prune -a --volumes -f


# Services
## node-load-balancer
### Start the service
nlb_start:
	docker compose up -d --build node-load-balancer_service

### Down the service
nlb_down:
	docker compose stop node-load-balancer_service

### Restart the service
nlb_restart:
	docker compose up -d --build node-load-balancer_service

### Show service's logs
nlb_logs:
	docker compose logs node-load-balancer_service

### Open an interactive bash shell
nlb_bash:
	docker exec -it node-load-balancer_container sh


## bitcoin-node
### Start the service
bn_start:
	docker compose up -d --build bitcoin-node_service

### Down the service
bn_down:
	docker compose stop bitcoin-node_service

### Restart the service
bn_restart:
	docker compose up -d --build bitcoin-node_service

### Show service's logs
bn_logs:
	docker compose logs bitcoin-node_service

### Open an interactive bash shell
bn_bash:
	docker exec -it bitcoin-node_container bash

### Set up workspace auth
bn_worksapce_chmod:
	docker exec -it bitcoin-node_container bash -c "find /root/.bitcoin -type d -exec chmod 777 {} \; && find /workspace -type f -exec chmod 666 {} \;"

### Clean bin
bn_clean_bin:
	docker exec -it bitcoin-node_container bash -c 'rm -rf /root/.bitcoin/*'




