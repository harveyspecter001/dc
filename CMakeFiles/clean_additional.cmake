# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Release")
  file(REMOVE_RECURSE
  "CMakeFiles\\dofus_process_sniffer_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\dofus_process_sniffer_autogen.dir\\ParseCache.txt"
  "DofusRedirect_autogen"
  "DofusTestDll_autogen"
  "dofus_process_sniffer_autogen"
  "minhook_autogen"
  )
endif()
