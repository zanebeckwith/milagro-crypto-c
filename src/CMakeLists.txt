# Create AMCL library

# Add the binary tree directory to the search path for linking and include files
link_directories( ${CMAKE_CURRENT_BINARY_DIR} )
include_directories (${CMAKE_CURRENT_BINARY_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_BINARY_DIR}/include )

set(SOURCES_AMCL
big.c
fp.c
ecp.c
hash.c
rand.c
aes.c
gcm.c
oct.c
rom.c
fp2.c
ecp2.c
fp4.c
fp12.c
ff.c)

# Build AMCL
add_library(amcl ${LIB_TYPE} ${SOURCES_AMCL} version.c)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  if(BUILD_SHARED_LIBS)
    message(STATUS "Build shared libs")
    target_link_libraries (amcl libm.so) 
  else()
    message(STATUS "Build static libs")
    target_link_libraries (amcl libm.a) 
  endif(BUILD_SHARED_LIBS)
endif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

# Build libmpin
if(BUILD_MPIN)
  message(STATUS "Build MPIN")
  add_library(mpin ${LIB_TYPE} pair.c mpin.c utils.c)
  target_link_libraries (mpin amcl) 
endif(BUILD_MPIN)

# Build libwcc
if(BUILD_WCC)
  message(STATUS "Build WCC")
  add_library(wcc ${LIB_TYPE} pair.c wcc.c utils.c)
  target_link_libraries (wcc amcl) 
endif(BUILD_WCC)

# Build libecdh
message(STATUS "Build ECDH")
add_library(ecdh ${LIB_TYPE} ecdh.c)
target_link_libraries (ecdh amcl) 

# Build librsa
message(STATUS "Build RSA")
add_library(rsa ${LIB_TYPE} rsa.c)
target_link_libraries (rsa amcl) 

# Copy built libs to test which allows testing without
# having to install the libs.
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    message(STATUS "Copy libamcl.dll to test for testing")
    add_custom_command(
                TARGET amcl
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl.dll" "${PROJECT_BINARY_DIR}/test/")

    add_custom_command(
                TARGET ecdh
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libecdh.dll" "${PROJECT_BINARY_DIR}/test/")

    add_custom_command(
                TARGET rsa
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/librsa.dll" "${PROJECT_BINARY_DIR}/test/")

    if(BUILD_MPIN)
      message(STATUS "Copy libmpin.dll to test for testing")
      add_custom_command(
                  TARGET mpin
                  POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libmpin.dll" "${PROJECT_BINARY_DIR}/test/")
    endif(BUILD_MPIN)

    if(BUILD_WCC)
      message(STATUS "Copy libwcc.dll to test for testing")
      add_custom_command(
                  TARGET wcc
                  POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libwcc.dll" "${PROJECT_BINARY_DIR}/test/")
    endif(BUILD_WCC)

endif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")

# Copy built libs to wrappers/python to allow testing without
# having to install the libs.
if (BUILD_PYTHON AND BUILD_SHARED_LIBS)

  if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

    message(STATUS "Copy libamcl.so to wrappers/python for testing")
    add_custom_command(
                TARGET amcl
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl.so" "${PROJECT_BINARY_DIR}/wrappers/python/")

    if(BUILD_MPIN)
      message(STATUS "Copy libmpin.so to wrappers/python for testing")
      add_custom_command(
                  TARGET mpin
                  POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libmpin.so" "${PROJECT_BINARY_DIR}/wrappers/python/")
    endif(BUILD_MPIN)

    if(BUILD_WCC)
      message(STATUS "Copy libwcc.so to wrappers/python for testing")
      add_custom_command(
                  TARGET wcc
                  POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libwcc.so" "${PROJECT_BINARY_DIR}/wrappers/python/")
    endif(BUILD_WCC)  

  endif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

  if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    message(STATUS "Copy libamcl.dll to wrappers/python for testing")
    add_custom_command(
                TARGET amcl
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl.dll" "${PROJECT_BINARY_DIR}/wrappers/python/")

    if(BUILD_MPIN)
      message(STATUS "Copy libmpin.dll to wrappers/python for testing")
      add_custom_command(
                  TARGET mpin
                  POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libmpin.dll" "${PROJECT_BINARY_DIR}/wrappers/python/")
    endif(BUILD_MPIN)

    if(BUILD_WCC)
      message(STATUS "Copy libwcc.dll to wrappers/python for testing")
      add_custom_command(
                  TARGET wcc
                  POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libwcc.dll" "${PROJECT_BINARY_DIR}/wrappers/python/")
    endif(BUILD_WCC)

  endif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")

  if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

    message(STATUS "Copy libamcl.dylib to wrappers/python for testing")
    add_custom_command(
                TARGET amcl
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl.dylib" "${PROJECT_BINARY_DIR}/wrappers/python/")

    if(BUILD_MPIN)
      message(STATUS "Copy libmpin.dylib to wrappers/python for testing")
      add_custom_command(
                  TARGET mpin
                  POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libmpin.dylib" "${PROJECT_BINARY_DIR}/wrappers/python/")
    endif(BUILD_MPIN)

    if(BUILD_WCC)
      message(STATUS "Copy libwcc.dylib to wrappers/python for testing")
      add_custom_command(
                  TARGET wcc
                  POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libwcc.dylib" "${PROJECT_BINARY_DIR}/wrappers/python/")
    endif(BUILD_WCC)  


  endif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")


endif (BUILD_PYTHON AND BUILD_SHARED_LIBS)


# Copy built libs to wrappers/go to allow testing without
# having to install the libs.
if (BUILD_GO AND BUILD_SHARED_LIBS)

  if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

    message(STATUS "Copy libamcl.so to wrappers/go for testing")
    add_custom_command(
                TARGET amcl
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl.so" "${PROJECT_BINARY_DIR}/wrappers/go/")

    if(BUILD_MPIN)
      message(STATUS "Copy libmpin.so to wrappers/go for testing")
      add_custom_command(
                  TARGET mpin
                  POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libmpin.so" "${PROJECT_BINARY_DIR}/wrappers/go/")
    endif(BUILD_MPIN)

    if(BUILD_WCC)
      message(STATUS "Copy libwcc.so to wrappers/go for testing")
      add_custom_command(
                  TARGET wcc
                  POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libwcc.so" "${PROJECT_BINARY_DIR}/wrappers/go/")
    endif(BUILD_WCC)  

  endif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

  if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    message(STATUS "Copy libamcl.dll to wrappers/go for testing")
    add_custom_command(
                TARGET amcl
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl.dll" "${PROJECT_BINARY_DIR}/wrappers/go/")

    if(BUILD_MPIN)
      message(STATUS "Copy libmpin.dll to wrappers/go for testing")
      add_custom_command(
                  TARGET mpin
                  POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libmpin.dll" "${PROJECT_BINARY_DIR}/wrappers/go/")
    endif(BUILD_MPIN)

    if(BUILD_WCC)
      message(STATUS "Copy libwcc.dll to wrappers/go for testing")
      add_custom_command(
                  TARGET wcc
                  POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libwcc.dll" "${PROJECT_BINARY_DIR}/wrappers/go/")
    endif(BUILD_WCC)

  endif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")

  if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

    message(STATUS "Copy libamcl.dylib to wrappers/go for testing")
    add_custom_command(
                TARGET amcl
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl.dylib" "${PROJECT_BINARY_DIR}/wrappers/go/")

    if(BUILD_MPIN)
      message(STATUS "Copy libmpin.dylib to wrappers/go for testing")
      add_custom_command(
                  TARGET mpin
                  POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libmpin.dylib" "${PROJECT_BINARY_DIR}/wrappers/go/")
    endif(BUILD_MPIN)

    if(BUILD_WCC)
      message(STATUS "Copy libwcc.dylib to wrappers/go for testing")
      add_custom_command(
                  TARGET wcc
                  POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libwcc.dylib" "${PROJECT_BINARY_DIR}/wrappers/go/")
    endif(BUILD_WCC)  


  endif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")


endif (BUILD_GO AND BUILD_SHARED_LIBS)

# Static build
if (BUILD_GO AND NOT BUILD_SHARED_LIBS)

  if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

    message(STATUS "Copy libamcl.so to wrappers/go for testing")
    add_custom_command(
                TARGET amcl
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl.a" "${PROJECT_BINARY_DIR}/wrappers/go/")

    if(BUILD_MPIN)
      message(STATUS "Copy libmpin.so to wrappers/go for testing")
      add_custom_command(
                  TARGET mpin
                  POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libmpin.a" "${PROJECT_BINARY_DIR}/wrappers/go/")
    endif(BUILD_MPIN)

    if(BUILD_WCC)
      message(STATUS "Copy libwcc.so to wrappers/go for testing")
      add_custom_command(
                  TARGET wcc
                  POST_BUILD
                  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libwcc.a" "${PROJECT_BINARY_DIR}/wrappers/go/")
    endif(BUILD_WCC)  

  endif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

endif (BUILD_GO AND NOT BUILD_SHARED_LIBS)

# Install libs
install(DIRECTORY DESTINATION lib DIRECTORY_PERMISSIONS
        OWNER_WRITE OWNER_READ OWNER_EXECUTE
        GROUP_WRITE GROUP_READ
        WORLD_WRITE WORLD_READ WORLD_EXECUTE)

install (TARGETS amcl rsa ecdh DESTINATION lib PERMISSIONS
        OWNER_WRITE OWNER_READ OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE)

if(BUILD_MPIN)
  install (TARGETS mpin DESTINATION lib PERMISSIONS
          OWNER_WRITE OWNER_READ OWNER_EXECUTE
          GROUP_READ GROUP_EXECUTE
          WORLD_READ WORLD_EXECUTE)
endif(BUILD_MPIN)

if(BUILD_WCC)
  install (TARGETS wcc DESTINATION lib PERMISSIONS
          OWNER_WRITE OWNER_READ OWNER_EXECUTE
          GROUP_READ GROUP_EXECUTE
          WORLD_READ WORLD_EXECUTE)
endif(BUILD_WCC)
