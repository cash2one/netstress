#
# Metin KAYA <kayameti@gmail.com>
# 2010.07.13, Istanbul
#
# http://www.EnderUNIX.org/metin
#

-include .config

VERSION		= v3.0.6
CC			= gcc
OUTPUT		= netstress
OSTYPE		= $(shell uname)
MCONF		= ./cfg/mconf.linux
LDLIBS		= -lrt
MAKEFLAGS	= --no-print-directory
CFLAGS		= -DVERSION=\"${VERSION}\" -DSTATIC_URL=\"${CONFIG_STATIC_URL}\"	\
			  -DHTTP_GET_HOST=\"${CONFIG_HTTP_GET_HOST}\" -Wall -W -O2			\
			  -Wstrict-prototypes -I./include -Wno-unused-result
NS_SOURCES  = $(foreach d, src, $(wildcard $(addprefix $(d)/*, .c)))
NS_OBJS     = $(addsuffix .o, $(basename $(NS_SOURCES)))

ifneq (${OSTYPE}, Linux)
MCONF   = ./cfg/mconf.bsd
CFLAGS += -DHOLYBSD
endif

CFLAGS-${CONFIG_STATIC_SRC_IP}			+= -DSTATIC_SRC_IP
CFLAGS-${CONFIG_RANDOM_SRC_IP}			+= -DRANDOM_SRC_IP
CFLAGS-${CONFIG_PATTERN_SRC_IP}			+= -DPATTERN_SRC_IP
CFLAGS-${CONFIG_RANDOM_COUNTRY_SRC_IP}	+= -DRANDOM_COUNTRY_SRC_IP
CFLAGS-${CONFIG_RANDOM_SRC_PORT}		+= -DRANDOM_SRC_PORT
CFLAGS-${CONFIG_RANDOM_DST_PORT}		+= -DRANDOM_DST_PORT
CFLAGS-${CONFIG_RANDOM_URL}				+= -DRANDOM_URL
CFLAGS += ${CFLAGS-y}


all:	clean ${NS_OBJS}
	${CC} -o ${OUTPUT} ${NS_OBJS} ${LDLIBS}
ifeq (${CONFIG_RANDOM_SRC_IP}, y)
ifeq (${CONFIG_RANDOM_SRC_PORT}, y)
	mv ${OUTPUT} ${OUTPUT}_fullrandom
else
	mv ${OUTPUT} ${OUTPUT}_randomip_staticport
endif
endif
ifeq (${CONFIG_PATTERN_SRC_IP}, y)
ifeq (${CONFIG_RANDOM_SRC_PORT}, y)
	mv ${OUTPUT} ${OUTPUT}_patternip_randomport
else
	mv ${OUTPUT} ${OUTPUT}_patternip_staticport
endif
endif
ifeq (${CONFIG_RANDOM_COUNTRY_SRC_IP}, y)
ifeq (${CONFIG_RANDOM_SRC_PORT}, y)
	mv ${OUTPUT} ${OUTPUT}_countryip_randomport
else
	mv ${OUTPUT} ${OUTPUT}_countryip_staticport
endif
endif
ifeq (${CONFIG_STATIC_SRC_IP}, y)
ifeq (${CONFIG_RANDOM_SRC_PORT}, y)
	mv ${OUTPUT} ${OUTPUT}_staticip_randomport
else
	mv ${OUTPUT} ${OUTPUT}_fullstatic
endif
endif
	@echo -e "\n\t\033[32mNetStress was successfully compiled...\033[0m\n"

config:
	${MCONF} cfg/NSconfig

menuconfig: config
	make all

clean:
	rm -f ${OUTPUT} ${OUTPUT}_*  src/*.o *~ src/*~ src/*.core

distclean: clean
	rm -f ..config.tmp .config.old .config
