set(CMAKE_AUTOMOC ON)

qt_add_executable(varta-gui
  main.cpp
  backend.hpp backend.cpp
  style.hpp style.cpp
  prompt.hpp prompt.cpp
  models.hpp models.cpp
  mainwindow.hpp mainwindow.cpp
)
target_link_libraries(varta-gui PRIVATE Qt6::Widgets Qt6::Network)
# A windowed (not console) program on Windows and a proper .app bundle on macOS.
# Without this Windows opens a terminal next to the GUI and closing it kills the app.
set_target_properties(varta-gui PROPERTIES WIN32_EXECUTABLE ON MACOSX_BUNDLE ON)
if(NOT MSVC)
  target_compile_options(varta-gui PRIVATE -Wall -Wextra)
endif()

# Ukrainian translation (optional: needs qt6-l10n-tools / Qt6LinguistTools).
find_package(Qt6 QUIET COMPONENTS LinguistTools)
if(Qt6LinguistTools_FOUND)
  qt_add_translations(varta-gui
    TS_FILES i18n/varta_uk.ts
    RESOURCE_PREFIX /i18n
    LUPDATE_OPTIONS -no-obsolete)
else()
  message(STATUS "Qt6 LinguistTools not found - GUI will be English only")
endif()

install(TARGETS varta-gui RUNTIME DESTINATION bin BUNDLE DESTINATION .)
