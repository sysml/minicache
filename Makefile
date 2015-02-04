default : all

# default build target
GITSHA1	?= $(shell git rev-parse --short HEAD || echo "?")
ARCH	?= x86_64
TARGET	?= minios

# user configuration
ifneq ("$(wildcard .config.mk)","")
include .config.mk
endif
# default configuration
include Config.mk

# build target specific configuration
include Target.$(TARGET).$(ARCH).mk
