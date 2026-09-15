#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "../include/hook_controller.h"

namespace py = pybind11;

PYBIND11_MODULE(wx_key, m) {
    m.doc() = "WeChat Key Hook Python Module (Hybrid: Auto DB + Optional Manual MD5)";

#ifdef _WIN32
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

        bool success = PollKeyData(key_buf.data(), static_cast<int>(key_buf.size()),
                                   md5_buf.data(), static_cast<int>(md5_buf.size()));

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
#else
    // Linux：initialize_hook 的第一个参数是微信可执行文件路径。
    // 扩展自行 fork+exec（PTRACE_TRACEME）拉起微信 —— 零提权；
    // AppImage 微信通过 FUSE 挂载，root 不可见，切勿以 root 运行。
    m.def("initialize_hook", [](const std::string& wechat_path) -> bool {
        return LinuxInitializeHook(wechat_path.c_str());
        }, "启动微信（TRACEME 自启动）并布防数据库密钥 Hook；成功后等待扫码登录",
        py::arg("wechat_path"));

    m.def("poll_key_data", []() -> py::object {
        char key_buf[65] = { 0 };
        if (!LinuxPollKeyData(key_buf, static_cast<int>(sizeof(key_buf)))) {
            return py::none();
        }
        py::dict result;
        result["key"] = std::string(key_buf);
        return result;
        }, "Poll for the captured DB key (64-hex string)");

    // Linux 图片密钥由 WCDA 的 image_key_resolver（纯 Python，kvcomm 派生）完成，
    // wx_key 不需要提供；这里保留同名入口返回 None 以维持 ABI 形状。
    m.def("get_image_key", []() -> py::object {
        return py::none();
        }, "Linux image keys are resolved locally by the consumer; returns None");
#endif

    m.def("get_status_message", []() -> py::object {
        char buffer[256] = { 0 };
        int level = 0;
#ifdef _WIN32
        bool has_msg = GetStatusMessage(buffer, sizeof(buffer), &level);
#else
        bool has_msg = LinuxGetStatusMessage(buffer, sizeof(buffer), &level);
#endif
        if (has_msg) {
            return py::make_tuple(std::string(buffer), level);
        }
        return py::make_tuple(py::none(), -1);
        }, "Get the next status message");

    m.def("cleanup_hook", []() -> bool {
#ifdef _WIN32
        return CleanupHook();
#else
        return LinuxCleanupHook();
#endif
        }, "Cleanup and uninstall the hook");

    m.def("get_last_error_msg", []() {
#ifdef _WIN32
        return std::string(GetLastErrorMsg());
#else
        return std::string(LinuxGetLastErrorMsg());
#endif
        }, "Get the last error message");
}