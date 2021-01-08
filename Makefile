WWWDIR=../www/static/obj

.PHONY: all web local clean local_clean web_clean

all:

env:
	( \
	  virtualenv -p python2 env; \
	  env/bin/pip install templite; \
	)

web: env
	$(foreach user,$(USERS), mkdir -p obj/$(user)/angr/solved; env/bin/python2 package.py obj/$(user)/angr; cp -R obj/$(user) $(WWWDIR))

local: env
	$(foreach user,$(USERS), env/bin/python2 package.py obj/$(user)/angr;)

clean: local_clean web_clean

local_clean:
	rm -rf obj
	rm -rf env

web_clean:
	rm -rf $(WWWDIR)/*
