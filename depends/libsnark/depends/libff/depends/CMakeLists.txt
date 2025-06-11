if(${CURVE} STREQUAL "BN128")
  include_directories(ate-pairing/include)
  include_directories(xbyak)
  add_library(
    zm
    STATIC

    ate-pairing/src/zm.cpp
    ate-pairing/src/zm2.cpp
  )
endif()

if(${CURVE} STREQUAL "MCL_BN128")
  include_directories(mcl/include)
  include_directories(xbyak)
  add_library(
    mcl
    STATIC

    mcl/src/fp.cpp
  )
endif()
