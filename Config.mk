######################################
## General
######################################
CONFIG_MINICACHE_HIDE_BANNER	?= n
CONFIG_MINICACHE_AUTOMOUNT	?= y
CONFIG_MINICACHE_MINDER_PRINT	?= n
CONFIG_MINICACHE_TRACE_BOOTTIME ?= y

######################################
## µSh
######################################
CONFIG_SHELL			?= y
CONFIG_SHELL_COLORPROMPT	?= y

######################################
## SHFS
######################################
CONFIG_SHFS_OPENBYNAME		?= y
CONFIG_SHFS_CACHEINFO		?= y

# Enable statistic capabilities of SHFS
#  If this option is disabled, STATS_HTTP is disabled as well
CONFIG_SHFS_STATS		?= y

# Advanced statistics from HTTP
#  This enables counting the number of successful downloads
#  (including range requests) and download progress
#  counters (see: DPCR)
CONFIG_SHFS_STATS_HTTP		?= y

# Download progress counters resolution (DPCR)
#  e.g., DPCR=6 means 6 counter values:
#  VAL1: HTTP request counts that downloaded >=   0% of file
#  VAL2: HTTP request counts that downloaded >=  20% of file
#  VAL3: HTTP request counts that downloaded >=  40% of file
#  VAL4: HTTP request counts that downloaded >=  60% of file
#  VAL5: HTTP request counts that downloaded >=  80% of file
#  VAL6: HTTP request counts that downloaded  = 100% of file
#
#  Note: DPCR has to be at least 2 for a 0% and 100% counter
#        otherwise this feature is disabled
CONFIG_SHFS_STATS_HTTP_DPCR	?= 6

######################################
## HTTP
######################################
# Enable http-info cmd in shell
CONFIG_HTTP_INFO		?= y
# Consider
CONFIG_HTTP_URL_CUTARGS		?= y
# Provide a performance test file on hash digest 0x0
CONFIG_HTTP_TESTFILE		?= n

######################################
## ctldir (only available on Mini-OS)
######################################
CONFIG_CTLDIR			?= y
CONFIG_CTLDIR_NOCHMOD		?= y

######################################
## Misc
######################################
CONFIG_TESTSUITE		?= n

######################################
## Debugging options
######################################
CONFIG_MINICACHE_IPERF_SERVER	?= n
CONFIG_HTABLE_DEBUG		?= n
CONFIG_MEMPOOL_DEBUG		?= n
CONFIG_SHFS_DEBUG		?= n
CONFIG_SHFS_CACHE_DEBUG		?= n
CONFIG_SHFS_CACHE_DISABLE	?= n
CONFIG_HTTP_DEBUG		?= n
CONFIG_HTTP_DEBUG_SESSIONSTATES	?= n
CONFIG_HTTP_DEBUG_PRINTACCESS	?= n
CONFIG_CTLDIR_DEBUG		?= n
