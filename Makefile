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
	docker run -p 12345:12345 -p 5000:$(shell cat config.yaml  |awk '{if ($$1 =="server:")print $$2;}'|awk -F : '{print $$2}'|awk -F \" '{print $$1}') certdemo

clean:
	@echo "rm cerdemo image"
	docker rmi certdemo  -f

replace:
	@echo $(shell ifconfig | grep 0xfff | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v 255)
	$(shell cd ./certdemo/templates &&  sed  's/SERVERIP/'$(shell ifconfig | grep 0xfff | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v 255)'/g' page4.htmld >page4.html)

check:./certdemo/templates/page4.html
	@echo "page4.html ip replaced"

