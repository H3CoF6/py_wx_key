import idc
import idaapi
import idautils


def main():
    print("\n" + "=" * 50)

    loop_pattern = "83 ?? 1F 0F B6 ?? ?? ?? 30"
    vcall_pattern = "48 8B 01 FF 50 10"

    candidates = set()
    current_ea = idaapi.cvar.inf.min_ea
    end_ea = idaapi.cvar.inf.max_ea

    while True:
        match_ea = idaapi.find_binary(current_ea, end_ea, loop_pattern, 16, idaapi.SEARCH_DOWN)
        if match_ea == idaapi.BADADDR:
            break
        if idaapi.is_code(idaapi.get_flags(match_ea)):
            func = idaapi.get_func(match_ea)
            if func:
                candidates.add(func.start_ea)
        current_ea = match_ea + 1

    target_func_ea = None
    for func_ea in candidates:
        func = idaapi.get_func(func_ea)
        if idaapi.find_binary(func.start_ea, func.end_ea, vcall_pattern, 16, idaapi.SEARCH_DOWN) != idaapi.BADADDR:
            target_func_ea = func.start_ea
            break

    if not target_func_ea:
        print("[-] 定位失败，核心业务特征已变更！")
        return

    print(f"[+] 目标函数基址: {hex(target_func_ea)}")
    print("-" * 50)


main()