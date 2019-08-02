build:Dockerfile
	@echo "build docker images for certdemo:"
	docker build . -t certdemo
run:config.yaml
	@echo  "run certdemo in docker:"
	docker run -p 5000:$(shell cat config.yaml  |awk '{if ($$1 =="server:")print $$2;}'|awk -F : '{print $$2}'|awk -F \" '{print $$1}') certdemo
clean:
	@echo "rm cerdemo image"
	docker rmi certdemo  -f
