WWWDIR=../www/static/obj

.PHONY: all web local clean local_clean web_clean

all:

env:
	( \
	  virtualenv -p python3 env; \
	  env/bin/pip install jinja2; \
	)

web: env
	$(foreach user,$(USERS), mkdir -p $(WWWDIR)/$(user)/angr/solved; env/bin/python package.py $(WWWDIR)/$(user)/angr;)

local: env
	$(foreach user,$(USERS), env/bin/python package.py obj/$(user)/angr;)

clean: local_clean web_clean

local_clean:
	rm -rf obj
	rm -rf env

web_clean:
	rm -rf $(WWWDIR)/*
