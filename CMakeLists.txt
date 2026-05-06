cmake_minimum_required(VERSION 3.20)
project(dofus_process_sniffer LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
# Evita fallo de AutoMoc en Windows (generación de moc_predefs.h).
set(CMAKE_AUTOMOC_COMPILER_PREDEFINES OFF)

find_package(Qt6 REQUIRED COMPONENTS Widgets Network)

if(WIN32)
    find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS "${Qt6_DIR}/../../../bin")
endif()

set(MINHOOK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/minhook")
set(MINHOOK_SOURCES
    "${MINHOOK_ROOT}/src/buffer.c"
    "${MINHOOK_ROOT}/src/hook.c"
    "${MINHOOK_ROOT}/src/trampoline.c"
    "${MINHOOK_ROOT}/src/hde/hde64.c"
)
add_library(minhook STATIC ${MINHOOK_SOURCES})
set_target_properties(minhook PROPERTIES AUTOMOC OFF)
target_include_directories(minhook PUBLIC "${MINHOOK_ROOT}/include")

set(DOFPS_SOURCES
    src/main.cpp
    src/ProcessEnumerator.cpp
    src/IriCardinalEmulator.cpp
    src/TcpMitmProxy.cpp
    src/IdDatabase.cpp
    src/PacketTypeOverrides.cpp
    src/ProtocolLogAnalyzer.cpp
    src/DiagnosticsLogWindow.cpp
    src/DebugCentralLog.cpp
    src/MainWindow.cpp
    src/ResourceAliasEditor.cpp
)

if (WIN32)
    list(APPEND DOFPS_SOURCES
         src/DllInjector.cpp
         src/WindowsTcpPidSnapshot.cpp
         src/WindowsTcpConnectionKiller.cpp
         src/ProcessMonitor.cpp)
endif()

add_executable(${PROJECT_NAME} ${DOFPS_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(${PROJECT_NAME} PRIVATE Qt6::Widgets Qt6::Network)

if (WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE shell32 ws2_32 iphlpapi user32)
    add_library(DofusRedirect SHARED src/dofus_redirect_dll.cpp)
    set_target_properties(DofusRedirect PROPERTIES AUTOMOC OFF)
    target_include_directories(DofusRedirect PRIVATE "${MINHOOK_ROOT}/include" src)
    target_link_libraries(DofusRedirect PRIVATE minhook ws2_32 mswsock iphlpapi)
    if(MINGW)
        target_link_options(DofusRedirect PRIVATE -static-libgcc -static-libstdc++)
        get_filename_component(MINGW_DLL_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
        foreach(DEP IN ITEMS libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll)
            if(EXISTS "${MINGW_DLL_DIR}/${DEP}")
                add_custom_command(
                    TARGET DofusRedirect
                    POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                            "${MINGW_DLL_DIR}/${DEP}"
                            $<TARGET_FILE_DIR:DofusRedirect>/${DEP}
                    COMMENT "Copiar ${DEP} junto a DofusRedirect.dll (LoadLibrary en Dofus)")
            endif()
        endforeach()
    endif()
    set_target_properties(DofusRedirect PROPERTIES OUTPUT_NAME "DofusRedirect" PREFIX "")
    add_library(DofusTestDll SHARED src/test_dll.cpp)
    set_target_properties(DofusTestDll PROPERTIES AUTOMOC OFF OUTPUT_NAME "DofusTestDll" PREFIX "")
    add_dependencies(${PROJECT_NAME} DofusRedirect DofusTestDll)
    add_custom_command(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:DofusRedirect>
                $<TARGET_FILE_DIR:${PROJECT_NAME}>/DofusRedirect.dll
        COMMENT "Copiar DofusRedirect.dll junto al ejecutable")
    add_custom_command(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:DofusTestDll>
                $<TARGET_FILE_DIR:${PROJECT_NAME}>/DofusTestDll.dll
        COMMENT "Copiar DofusTestDll.dll junto al ejecutable")
    if(WINDEPLOYQT_EXECUTABLE)
        add_custom_command(
            TARGET ${PROJECT_NAME}
            POST_BUILD
            COMMAND "${WINDEPLOYQT_EXECUTABLE}"
                    "$<TARGET_FILE:${PROJECT_NAME}>"
                    --release
                    --compiler-runtime
            COMMENT "windeployqt: copiar Qt6Core.dll y dependencias junto al .exe")
    endif()
endif()

if (MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /utf-8)
endif()
