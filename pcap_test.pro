TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    jpcaplib.cpp \
    printdata.cpp

HEADERS += \
    jpcaplib.h \
    printdata.hpp

LIBS += -lpcap
