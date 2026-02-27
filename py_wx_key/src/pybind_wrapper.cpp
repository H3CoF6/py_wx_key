#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <Windows.h>
#include "../include/hook_controller.h"

namespace py = pybind11;

PYBIND11_MODULE(wx_key, m) {
    m.doc() = "WeChat Key Hook Python Module (Dual Hooks)";

    m.def("initialize_hook", &InitializeHook,
        "Initialize and install the dual hooks",
        py::arg("target_pid"),
        py::arg("version") = "",
        py::arg("key_pattern"), py::arg("key_mask"), py::arg("key_offset"),
        py::arg("md5_pattern"), py::arg("md5_mask"), py::arg("md5_offset"));

    m.def("poll_key_data", []() -> py::object {
        std::vector<char> key_buf(65, 0);
        std::vector<char> md5_buf(33, 0);

        bool success = PollKeyData(key_buf.data(), 65, md5_buf.data(), 33);

        if (success) {
            py::dict result;
            if (key_buf[0] != '\0') {
                result["key"] = std::string(key_buf.data());
            }
            if (md5_buf[0] != '\0') {
                result["md5"] = std::string(md5_buf.data());
            }
            return result;
        }

        return py::none();
        }, "Poll for new data, returns a dict {'key': '...', 'md5': '...'} or None");

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