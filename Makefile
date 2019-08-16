build:Dockerfile
	@echo "replace ip in page4.html"
	make replace
	@echo "checking"
	make check
	@echo "ip replaced"
	@echo "build docker images for certdemo:"
	docker build . -t certdemo
	cp certdemo/config.yaml .

run:config.yaml
	@echo  "run certdemo in docker:"
	docker run  -d -p 12345:12345 -p $(shell cat config.yaml  |awk '{if ($$1 =="server:")print $$2;}'|awk -F : '{print $$2}'|awk -F \" '{print $$1}'):5000  certdemo 

stop:
	@echo "rm certdemo container"
	docker rm $(shell docker ps |grep certdemo |awk '{print $$1}') -f

clean:
	@echo "rm cerdemo image"
	docker rmi certdemo  -f

replace:
	@echo $(shell curl -s ifconfig.me )
	$(shell cd ./certdemo/templates &&  sed  's/SERVERIP/'$(shell curl -s ifconfig.me )'/g' page4.htmld >page4.html)

check:./certdemo/templates/page4.html
	@echo "page4.html ip replaced"

