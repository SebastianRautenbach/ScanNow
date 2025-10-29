workspace "ScanNow"
    architecture "x64"

    configurations
    {
        "Debug", "Release"
    }

outputdir = "%{cfg.buildcfg}-%{cfg.system}-%{cfg.architecture}"

project "ScanNow"
    kind "StaticLib"
    language "C++"
    cppdialect "C++17"
    staticruntime "on"

    warnings "Extra"    

    targetdir ("ScanNow/bin/" .. outputdir .. "/%{prj.name}")

    files
    {
        "ScanNow/include/thirdparty/sqlite3.c",  
        "ScanNow/src/**.cpp",
        "ScanNow/src/**.c",
        "ScanNow/include/**.h",
        "ScanNow/include/**.hpp"
    }

    includedirs
    {
        "ScanNow/include"        
    }

    libdirs 
    {
        "ScanNow/lib"
    }

    links 
    {
    }

    filter "system.windows"
        systemversion "latest"


    filter "configurations:Debug"
        runtime "Debug"
        staticruntime "On"
        symbols "On"

    filter "configurations:Release"
        runtime "Release"
        staticruntime "On"
        optimize "On"


project "ScanNowDebug"

    kind "ConsoleApp"
    language "C++"
    cppdialect "C++17"
    staticruntime "on"

    warnings "Extra"    


    targetdir ("ScanNowDebug/bin/" .. outputdir .. "/%{prj.name}")

     files
    {        
        "ScanNowDebug/include/dependencies/glad.c",
        "ScanNowDebug/include/dependencies/imgui/backends/imgui_impl_glfw.cpp",
        "ScanNowDebug/include/dependencies/imgui/backends/imgui_impl_opengl3.cpp",
        "ScanNowDebug/include/dependencies/imgui/imgui.cpp",
        "ScanNowDebug/include/dependencies/imgui/imgui_demo.cpp",
        "ScanNowDebug/include/dependencies/imgui/imgui_draw.cpp",
        "ScanNowDebug/include/dependencies/imgui/imgui_tables.cpp",
        "ScanNowDebug/include/dependencies/imgui/imgui_widgets.cpp",                        
        "ScanNowDebug/include/dependencies/tinyfiledialogs.c",
        "ScanNowDebug/src/**.cpp",
        "ScanNowDebug/src/**.c",
        "ScanNowDebug/include/**.h",
        "ScanNowDebug/include/**.hpp"
    }

    includedirs
    {
        "ScanNowDebug/include",
        "ScanNowDebug/include/dependencies",
        "ScanNowDebug/include/dependencies/imgui",
        "ScanNow/include/scanner"
           
    }

    libdirs 
    {
        "ScanNowDebug/lib",
        "ScanNow/bin/" .. outputdir .. "/ScanNow"
    }

    links 
    {
        "ScanNow",
        "glfw3dll",
        "opengl32",
    }

    filter "system.windows"
        systemversion "latest"


    filter "configurations:Debug"
        runtime "Debug"
        staticruntime "On"
        symbols "On"

    filter "configurations:Release"
        runtime "Release"
        staticruntime "On"
        optimize "On"