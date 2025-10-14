workspace "ScanNow"
    architecture "x64"

    configurations
    {
        "Debug",
        "Release"
    }

outputdir = "%{cfg.buildcfg}-%{cfg.system}-%{cfg.architecture}"


project "ScanNow"
    kind "WindowedApp"
    language "C++"
    cppdialect "C++17"
    staticruntime "on"

    warnings "Extra"    


    targetdir ("bin/" .. outputdir .. "/%{prj.name}")

    files
    {
        "include/thirdparty/sqlite3.c",  
        "src/**.cpp",
        "src/**.c",
        "include/**.h",
        "include/**.hpp"
    }

    includedirs
    {
        "include"        
    }

    libdirs 
    {
        "lib"
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