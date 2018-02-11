PROGRAM_NAME = analyzer

CFLAGS = -Wall
DEPS = lists.h
OBJECT_FILES = $(PROGRAM_NAME).o lists.o

$(PROGRAM_NAME) : $(OBJECT_FILES)
	gcc $(CFLAGS) -o $@ $(OBJECT_FILES)

$(PROGRAM_NAME).o : $(PROGRAM_NAME).c $(DEPS)
	gcc $(CFLAGS) -c $<

clean :
	$(RM) $(PROGRAM_NAME)
	$(RM) $(OBJECT_FILES)
	$(RM) *~
