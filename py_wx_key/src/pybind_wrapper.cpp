#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <Windows.h>
#include "../include/hook_controller.h"

namespace py = pybind11;

PYBIND11_MODULE(wx_key, m) {
    m.doc() = "WeChat Key Hook Python Module (Hybrid: Auto DB + Optional Manual MD5)";

    m.def("initialize_hook", &InitializeHook,
        "Initialize and install hook. Always hooks DB Key (Auto). Hooks Image Key only if md5 parameters are provided.",
        py::arg("target_pid"),
        py::arg("md5_pattern") = py::none(), 
        py::arg("md5_mask") = py::none(), 
        py::arg("md5_offset") = 0);

    m.def("get_image_key", []() -> py::object {
        char buffer[8192] = { 0 };
        bool success = GetImageKey(buffer, sizeof(buffer));
        if (success) {
            return py::cast(std::string(buffer));
        }
        return py::none();
        }, "Get image keys from local files (No hook needed), returns JSON string or None");

    m.def("poll_key_data", []() -> py::object {
        std::vector<char> key_buf(65, 0);
        std::vector<char> md5_buf(128, 0);

        bool success = PollKeyData(key_buf.data(), 65, md5_buf.data(), 128);

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
        }, "Poll for new captured data");

    m.def("get_status_message", []() -> py::object {
        char buffer[256] = { 0 };
        int level = 0;
        bool has_msg = GetStatusMessage(buffer, sizeof(buffer), &level);
        if (has_msg) {
            return py::make_tuple(std::string(buffer), level);
        }
        return py::make_tuple(py::none(), -1);
        }, "Get the next status message");

    m.def("cleanup_hook", &CleanupHook, "Cleanup and uninstall the hook");

    m.def("get_last_error_msg", []() {
        return std::string(GetLastErrorMsg());
        }, "Get the last error message");
}
