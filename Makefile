NAME = a.out
CC = g++
SRC = $(shell find . -name "*.cpp")
FLAGS = -I.  -lssl -lcrypto
PWD = $(shell pwd)
#-L/goinfre/oyumusak/homebrew/opt/openssl@3/lib -I/goinfre/oyumusak/homebrew/opt/openssl@3/include -I manageapi  -I socketmanager 

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
     FLAGS +=
endif
ifeq ($(UNAME_S),Darwin)
    FLAGS += -L $(PWD)/openssl@3/3.0.7/lib -I $(PWD)/openssl@3/3.0.7/include
endif

all:
	$(CC) $(SRC) $(FLAGS) -o $(NAME)