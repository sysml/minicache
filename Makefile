default : all

# default build target
GITSHA1	?= $(shell git rev-parse --short HEAD || echo "?")
ARCH	?= x86_64
TARGET	?= minios

# default configuration
include Config.mk
# user configuration
ifneq ("$(wildcard .config.mk)","")
include .config.mk
endif

# build target specific configuration
include Minicache.mk
include Target.$(TARGET).$(ARCH).mk
