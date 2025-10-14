workspace "ScanNow"
    architecture "x64"

    configurations
    {
        "DebugLib", "ReleaseLib"
    }

outputdir = "%{cfg.buildcfg}-%{cfg.system}-%{cfg.architecture}"


project "ScanNow"
    kind "StaticLib"
    language "C++"
    cppdialect "C++17"
    staticruntime "on"

    warnings "Extra"    

targetdir ("ScanNowDebug/lib")
--    targetdir ("ScanNow/bin/" .. outputdir .. "/%{prj.name}")

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
        "ScanNowDebug/src/**.cpp",
        "ScanNowDebug/src/**.c",
        "ScanNowDebug/include/**.h",
        "ScanNowDebug/include/**.hpp"
    }

    includedirs
    {
        "ScanNowDebug/include",
        "ScanNow/include/scanner"     
    }

    libdirs 
    {
        "ScanNowDebug/lib"
    }

    links 
    {
        "ScanNow.lib"
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


