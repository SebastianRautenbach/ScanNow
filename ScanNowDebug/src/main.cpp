#include <iostream>
#include <vector>
#include <string>

#include "scanner.h"                 

#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include "imgui/imgui.h"
#include "imgui/backends/imgui_impl_glfw.h"
#include "imgui/backends/imgui_impl_opengl3.h"

// --------------------------------------------------------------------- GLOBALS
std::vector<std::string> g_scanResults;
bool g_scanRunning = false;
bool g_scanComplete = false;


void function_callback(const lowlevel::QuarantineItem& item)
{
    g_scanResults.push_back(item.location);
    std::cout << "Found: " << item.location << "\n";
}

// ---------------------------------------------------------------------GLFW error callback

static void glfw_error_callback(int error, const char* description)
{
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

// ---------------------------------------------------------------------
int main()
{

    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW\n";
        return -1;
    }

    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    GLFWwindow* window = glfwCreateWindow(800, 600, "Scanner – ImGui", nullptr, nullptr);
    if (!window) {
        std::cerr << "Failed to create GLFW window\n";
        glfwTerminate();
        return -1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);               

    if (!gladLoadGLLoader((GLADloadproc)glfwGetProcAddress)) {
        std::cerr << "Failed to initialize GLAD\n";
        return -1;
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);
    ImGui::StyleColorsDark();


    scannow::ScanNow scanner;
    scanner.Initialize();


    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();

      
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

       
        ImGui::Begin("Scanner Results");

        if (ImGui::Button("Start Scan") && !g_scanRunning)
        {
            g_scanResults.clear();
            g_scanComplete = false;
            g_scanRunning = true;

           
            scanner.scan(function_callback);

            g_scanRunning = false;
            g_scanComplete = true;
        }

        ImGui::SameLine();
        if (g_scanRunning) {
            ImGui::Text("Scanning…");
        }
        else if (g_scanComplete) {
            ImGui::Text("Scan complete – %d item(s) found.", (int)g_scanResults.size());
        }
        else {
            ImGui::Text("Ready to scan.");
        }

        ImGui::Separator();

      
        if (ImGui::BeginChild("Results", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar))
        {
            for (const auto& path : g_scanResults)
                ImGui::TextUnformatted(path.c_str());
            ImGui::EndChild();
        }

        ImGui::End();

       
        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(0.15f, 0.15f, 0.15f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

  
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}