CPP=g++
SOURCE_FILES=rules_to_pcre.cpp
PROGRAM_NAME=rules_to_pcre

all:
	$(CPP) $(SOURCE_FILES) -lpcrecpp -lboost_filesystem -lboost_program_options -lboost_system -o$(PROGRAM_NAME)

clean:
	rm -f $(PROGRAM_NAME)
