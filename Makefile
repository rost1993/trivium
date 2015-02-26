CC=gcc
CFLAGS=-Wall -O2
SOURCES=./trivium_sources

MAIN_OBJS=trivium.o main.o
BIGTEST_OBJS=bigtest.o trivium.o
TEST_VECTORS_OBJS=trivium.o testvectors.o

MAIN_DEVELOPER_OBJS=$(patsubst %, $(SOURCES)/%, trivium.o ecrypt-sync.o main.o)
BIGTEST_DEVELOPER_OBJS=$(patsubst %, $(SOURCES)/%, trivium.o ecrypt-sync.o bigtest_2.o)

MAIN=main
BIGTEST=bigtest
TEST_VECTORS=testvectors

MAIN_DEVELOPER=$(SOURCES)/main
BIGTEST_DEVELOPER=$(SOURCES)/bigtest_2

all: $(MAIN) $(BIGTEST) $(MAIN_DEVELOPER) $(BIGTEST_DEVELOPER)

.c.o:
	$(CC) $(CFLAGS) -c $^ -o $@
	
$(MAIN): $(MAIN_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(BIGTEST): $(BIGTEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_VECTORS): $(TEST_VECTORS_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(MAIN_DEVELOPER): $(MAIN_DEVELOPER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(BIGTEST_DEVELOPER): $(BIGTEST_DEVELOPER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o $(SOURCES)/*.o
	rm -f $(MAIN) $(BIGTEST) $(MAIN_DEVELOPER) $(BIGTEST_DEVELOPER)

.PHONY: test
test:
	bash test_trivium.sh
