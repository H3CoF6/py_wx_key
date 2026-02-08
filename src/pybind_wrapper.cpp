#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <Windows.h>
#include "../include/hook_controller.h"

namespace py = pybind11;

PYBIND11_MODULE(wx_key, m) {
    m.doc() = "WeChat Key Hook Python Module (ABI3 Compatible)";

    m.def("initialize_hook", &InitializeHook, 
          "Initialize and install the hook",
          py::arg("target_pid"), 
          py::arg("version") = "", 
          py::arg("pattern"), 
          py::arg("mask"), 
          py::arg("offset"));

    m.def("poll_key_data", [](int buffer_size) -> py::object {
        // 初始化 vector 并填零，防止乱码
        std::vector<char> buffer(buffer_size, 0);

        bool success = PollKeyData(buffer.data(), buffer_size);

        if (success) {
            // 确保只转换有效字符串部分
            return py::cast(std::string(buffer.data()));
        }

        // 失败返回 None
        return py::none();
        }, "Poll for new key data, returns hex string or None",
        py::arg("buffer_size") = 65);

    // ---------------------------------------------------------
    // 修复点：get_status_message
    // 同样添加 -> py::object 明确返回类型
    // ---------------------------------------------------------
    m.def("get_status_message", []() -> py::object {
        char buffer[256] = { 0 }; // 也就是初始化为0
        int level = 0;

        bool has_msg = GetStatusMessage(buffer, sizeof(buffer), &level);

        if (has_msg) {
            return py::make_tuple(std::string(buffer), level);
        }

        return py::make_tuple(py::none(), -1);
        }, "Get the next status message, returns (message, level) or (None, -1)");

    m.def("cleanup_hook", &CleanupHook, "Cleanup and uninstall the hook");

    m.def("get_last_error_msg", []() {
        return std::string(GetLastErrorMsg());
        }, "Get the last error message");
}