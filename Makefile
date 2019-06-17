
SUBDIRS := src
SUBCLEAN = $(addsuffix .clean,$(SUBDIRS))

all: $(SUBDIRS)
clean: $(SUBCLEAN)

$(SUBDIRS):
	$(MAKE) -C $@ $(TARGET)

$(SUBCLEAN): %.clean:
	$(MAKE) -C $* clean

.PHONY: all clean $(SUBDIRS) $(SUBCLEAN)
