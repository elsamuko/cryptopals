
QMAKE_CXXFLAGS += -maes
QMAKE_CXXFLAGS_RELEASE += -msse2 -Ofast -march=native
QMAKE_LFLAGS_RELEASE += -flto

LIBS += -lstdc++fs -lpthread -lrt

# sudo add-apt-repository ppa:ubuntu-toolchain-r/test
# sudo apt update
# sudo apt install g++-10
QMAKE_CC = gcc-10
QMAKE_CXX = g++-10
